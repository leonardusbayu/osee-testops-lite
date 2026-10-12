package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"osee-testops-lite/internal/integrations"
)

func validPollerConfig() pollerConfig {
	return pollerConfig{Enabled: true, Staging: true, TableID: pollerTableID, Dartboard: pollerDartboard, TinyCredentialsFile: ".local/integrations/tinycommand.json", DartTokenFile: ".local/integrations/dart-token", SourceSecretFile: ".local/integrations/tinycommand-source-secret"}
}

func TestPollerConfigurationDefaultsDisabled(t *testing.T) {
	if err := validatePollerConfig(pollerConfig{}, false); err != nil {
		t.Fatal("zero configuration should be a no-op")
	}
	if err := validatePollerConfig(validPollerConfig(), false); !errors.Is(err, errPollerConfig) {
		t.Fatal("enabled without once accepted")
	}
	var output bytes.Buffer
	path := filepath.Join(t.TempDir(), "missing.json")
	if code := run([]string{"-config", path}, &output); code != 0 || !strings.Contains(output.String(), "disabled") {
		t.Fatalf("missing config contacted dependencies: %d", code)
	}
}

type testSchemaSource struct {
	table         integrations.TinyTable
	reads, writes int
}

func (s *testSchemaSource) Table(context.Context) (integrations.TinyTable, error) {
	return s.table, nil
}
func (s *testSchemaSource) Rows(context.Context, int, int) (integrations.TinyRowsPage, error) {
	s.reads++
	return integrations.TinyRowsPage{}, nil
}
func (s *testSchemaSource) Ack(context.Context, string, integrations.TinyAcknowledgment) error {
	s.writes++
	return nil
}

func TestPollerSchemaDriftStopsReadsAndAcknowledgments(t *testing.T) {
	source := &testSchemaSource{table: integrations.TinyTable{ID: pollerTableID}}
	guarded := schemaGuardedQueue{source: source}
	if _, err := guarded.Rows(context.Background(), 0, 100); err == nil || source.reads != 0 {
		t.Fatal("schema drift returned task candidates")
	}
	if err := guarded.Ack(context.Background(), "row_1", integrations.TinyAcknowledgment{Status: "ACKNOWLEDGED", ReceiptID: "receipt_1"}); err == nil || source.writes != 0 {
		t.Fatal("schema drift reached acknowledgment write")
	}
}

func TestPollerDisabledFileDoesNotLoadEnvironmentOrCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disabled.json")
	if err := os.WriteFile(path, []byte(`{"enabled":false,"tiny_credentials_file":"does-not-exist"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_ENV", "production")
	var output bytes.Buffer
	if run([]string{"-config", path, "-once"}, &output) != 0 || !strings.Contains(output.String(), "disabled") {
		t.Fatal("disabled file touched environment or credentials")
	}
}

func TestPollerConfigurationRejectsBroaderScope(t *testing.T) {
	for _, change := range []func(*pollerConfig){
		func(c *pollerConfig) { c.Staging = false }, func(c *pollerConfig) { c.TableID = "other-table" }, func(c *pollerConfig) { c.Dartboard = "Other/Tasks" },
		func(c *pollerConfig) { c.TinyCredentialsFile = "" }, func(c *pollerConfig) { c.DartTokenFile = "../../token" }, func(c *pollerConfig) { c.SourceSecretFile = ".local/elsewhere/token" },
	} {
		c := validPollerConfig()
		change(&c)
		if !errors.Is(validatePollerConfig(c, true), errPollerConfig) {
			t.Fatal("broader scope accepted")
		}
	}
	if err := validatePollerConfig(validPollerConfig(), true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(validPollerConfig().String()), "token") {
		t.Fatal("config formatter includes path/credential context")
	}
}

func TestPollerStrictFiles(t *testing.T) {
	for _, body := range []string{`{"enabled":true,"enabled":false}`, `{"unexpected":"secret-value"}`, `{} {}`, `[]`, strings.Repeat(" ", maximumFileBytes+1)} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		var cfg pollerConfig
		if err := readStrictFile(path, &cfg); !errors.Is(err, errPollerConfig) || strings.Contains(err.Error(), "secret-value") {
			t.Fatal("unsafe file accepted or leaked")
		}
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"enabled":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	var cfg pollerConfig
	if err := readStrictFile(path, &cfg); err != nil || cfg.Enabled {
		t.Fatal("disabled file invalid")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := readStrictFile(path, &cfg); runtime.GOOS != "windows" && err == nil {
		t.Fatal("unprotected Unix file accepted")
	}
}

func TestPollerFullQueueSchemaGate(t *testing.T) {
	good := integrations.TinyTable{ID: pollerTableID, Name: "osee.co.id TestOps Outbox - STAGING"}
	for i, name := range queueColumns {
		good.Columns = append(good.Columns, integrations.TinyColumn{ID: string(rune('a' + i)), Name: name, Type: "text"})
	}
	if err := validateQueueSchema(good); err != nil {
		t.Fatal(err)
	}
	wrongID := good
	wrongID.ID = "other"
	if validateQueueSchema(wrongID) == nil {
		t.Fatal("other table accepted")
	}
	missing := good
	missing.Columns = missing.Columns[1:]
	if validateQueueSchema(missing) == nil {
		t.Fatal("missing input field accepted")
	}
	drift := good
	drift.Columns = append([]integrations.TinyColumn(nil), good.Columns...)
	drift.Columns[0].Type = "number"
	if validateQueueSchema(drift) == nil {
		t.Fatal("unexpected API type accepted")
	}
	duplicate := good
	duplicate.Columns = append(append([]integrations.TinyColumn(nil), good.Columns...), good.Columns[0])
	if validateQueueSchema(duplicate) == nil {
		t.Fatal("duplicate schema mapping accepted")
	}
	alias := good
	alias.Columns = append([]integrations.TinyColumn(nil), good.Columns...)
	alias.Columns[0].Name = strings.ToUpper(alias.Columns[0].Name)
	if validateQueueSchema(alias) == nil {
		t.Fatal("case alias accepted")
	}
}

func TestPollerRejectsUnsafeArguments(t *testing.T) {
	var output bytes.Buffer
	if run([]string{"-unknown=secret-value"}, &output) == 0 || strings.Contains(output.String(), "secret-value") {
		t.Fatal("argument error not redacted")
	}
	output.Reset()
	if run([]string{"extra-payload"}, &output) == 0 || strings.Contains(output.String(), "extra-payload") {
		t.Fatal("arbitrary payload accepted")
	}
}
func TestPollerRejectsCredentialParentSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	t.Chdir(root)
	if err := os.Mkdir(".local", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "token"), []byte("synthetic-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(".local", "integrations")); err != nil {
		t.Skip("OS cannot create test symlink")
	}
	file, err := openProtected(filepath.Join(".local", "integrations", "token"))
	if file != nil {
		file.Close()
	}
	if !errors.Is(err, errPollerConfig) {
		t.Fatal("credential parent link escaped protected boundary")
	}
}
