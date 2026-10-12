// integration-poller is an explicitly enabled, one-shot staging worker. It
// makes outbound cloud calls but exposes no listener and runs no migrations.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"osee-testops-lite/internal/config"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/integrations"
)

const pollerTableID = "cmv0m8pgc0wglh7nyr0u9p0eu"
const pollerDartboard = "osee.co.id TestOps/Tasks"
const maximumFileBytes = 65536

var errPollerConfig = errors.New("invalid protected poller configuration")
var errQueueSchema = errors.New("queue schema unavailable or changed; worker not ready")
var queueColumns = []string{"event_id", "source", "kind", "object_id", "source_version", "receipt_id", "last_error", "envelope_json", "queue_status"}

type pollerConfig struct {
	Enabled             bool   `json:"enabled"`
	Staging             bool   `json:"staging"`
	TableID             string `json:"table_id"`
	Dartboard           string `json:"dartboard"`
	TinyCredentialsFile string `json:"tiny_credentials_file"`
	DartTokenFile       string `json:"dart_token_file"`
	SourceSecretFile    string `json:"source_secret_file"`
}

func (pollerConfig) String() string     { return "pollerConfig{protected:redacted}" }
func (c pollerConfig) GoString() string { return c.String() }

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

// run deliberately reports only safe fixed messages and count summaries.
func run(args []string, output io.Writer) int {
	flags := flag.NewFlagSet("integration-poller", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", ".local/integrations/poller.json", "protected local configuration file")
	once := flags.Bool("once", false, "required one-shot staging run")
	fail := func(message string) int { fmt.Fprintln(output, message); return 1 }
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return fail("invalid poller arguments")
	}
	var settings pollerConfig
	if _, err := os.Lstat(*path); os.IsNotExist(err) {
		fmt.Fprintln(output, "integration poller disabled; no requests made")
		return 0
	}
	if readStrictFile(*path, &settings) != nil || validatePollerConfig(settings, *once) != nil {
		return fail("invalid protected poller configuration")
	}
	if !settings.Enabled {
		fmt.Fprintln(output, "integration poller disabled; no requests made")
		return 0
	}
	local, err := config.Load()
	if err != nil {
		return fail("isolated development environment required")
	}
	var credentials struct {
		APIKey string `json:"api_key"`
	}
	if readStrictFile(settings.TinyCredentialsFile, &credentials) != nil {
		return fail("protected TinyCommand credential unavailable")
	}
	tiny, err := integrations.NewTinyClient(integrations.TinyConfig{APIKey: credentials.APIKey, TableID: pollerTableID})
	if err != nil {
		return fail("TinyCommand credential configuration invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// No DB or Dart provider is opened until the exact queue schema is verified.
	table, err := tiny.Table(ctx)
	if err != nil || validateQueueSchema(table) != nil {
		return fail("queue API or exact schema unavailable; worker not ready")
	}
	token, err := readSecretFile(settings.DartTokenFile, maximumFileBytes)
	if err != nil {
		return fail("protected Dart credential unavailable")
	}
	secret, err := readSecretFile(settings.SourceSecretFile, 256)
	if err != nil || len(secret) < 32 {
		return fail("protected internal source secret unavailable")
	}
	dart, err := integrations.NewDartMCP(token, nil)
	if err != nil {
		return fail("Dart credential configuration invalid")
	}
	store, err := db.Open(ctx, local.DatabaseURL)
	if err != nil {
		return fail("isolated local database unavailable")
	}
	defer store.Close()
	// The approved schema must already exist; never invoke Store.Migrate here.
	receiver, err := integrations.NewEventGateway(store, integrations.EventConfig{Secrets: map[string][]byte{"tinycommand": []byte(secret)}})
	if err != nil {
		return fail("internal receipt boundary unavailable")
	}
	tasks, err := integrations.NewDartSynchronizer(store, dart, integrations.DartSyncConfig{Dartboard: pollerDartboard, Statuses: map[string]string{"open": "To-do", "in_progress": "Doing", "done": "Done"}, Staging: true})
	if err != nil {
		return fail("staging task mapping unavailable")
	}
	queue := schemaGuardedQueue{source: tiny}
	worker, err := integrations.NewQueuePoller(queue, receiver, tasks, []byte(secret))
	if err != nil {
		return fail("bounded queue worker unavailable")
	}
	summary, err := worker.Poll(ctx)
	data, encodeErr := json.Marshal(summary)
	if encodeErr != nil {
		return fail("safe poll summary unavailable")
	}
	fmt.Fprintln(output, string(data))
	if err != nil {
		return fail("poll incomplete; preserve durable receipts and reconcile before retry")
	}
	return 0
}

func validatePollerConfig(c pollerConfig, once bool) error {
	if !c.Enabled {
		return nil
	}
	if !once || !c.Staging || c.TableID != pollerTableID || c.Dartboard != pollerDartboard {
		return errPollerConfig
	}
	for _, path := range []string{c.TinyCredentialsFile, c.DartTokenFile, c.SourceSecretFile} {
		if !protectedPath(path) {
			return errPollerConfig
		}
	}
	paths := []string{c.TinyCredentialsFile, c.DartTokenFile, c.SourceSecretFile}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			if filepath.Clean(paths[i]) == filepath.Clean(paths[j]) {
				return errPollerConfig
			}
		}
	}
	return nil
}

func protectedPath(path string) bool {
	if path == "" || filepath.IsAbs(path) || filepath.ToSlash(filepath.Clean(path)) != filepath.ToSlash(path) {
		return false
	}
	root, err := filepath.Abs(filepath.Join(".local", "integrations"))
	if err != nil {
		return false
	}
	target, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func openProtected(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errPollerConfig
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || (runtime.GOOS == "windows" && !strings.EqualFold(absolute, resolved)) || (runtime.GOOS != "windows" && absolute != resolved) {
		return nil, errPollerConfig
	}
	for parent := filepath.Dir(absolute); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errPollerConfig
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumFileBytes {
		return nil, errPollerConfig
	}
	// Unix files must be owner-only. Windows uses NTFS ACLs; the operator must
	// restrict these files to the integration owner, SYSTEM and Administrators.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errPollerConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errPollerConfig
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) {
		file.Close()
		return nil, errPollerConfig
	}
	return file, nil
}

func readStrictFile(path string, destination any) error {
	file, err := openProtected(path)
	if err != nil {
		return errPollerConfig
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maximumFileBytes+1))
	if err != nil || len(body) > maximumFileBytes || rejectDuplicateKeys(body) != nil {
		return errPollerConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(new(any)) != io.EOF {
		return errPollerConfig
	}
	return nil
}

func readSecretFile(path string, maximum int) (string, error) {
	file, err := openProtected(path)
	if err != nil {
		return "", errPollerConfig
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, int64(maximum+3)))
	if err != nil || len(body) > maximum+2 {
		return "", errPollerConfig
	}
	value := strings.TrimRight(string(body), "\r\n")
	if len(value) == 0 || len(value) > maximum {
		return "", errPollerConfig
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return "", errPollerConfig
		}
	}
	return value, nil
}

func rejectDuplicateKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return errPollerConfig
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || name != strings.ToLower(name) || seen[name] {
					return errPollerConfig
				}
				seen[name] = true
				if walk() != nil {
					return errPollerConfig
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errPollerConfig
			}
		case '[':
			for decoder.More() {
				if walk() != nil {
					return errPollerConfig
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errPollerConfig
			}
		default:
			return errPollerConfig
		}
		return nil
	}
	if walk() != nil {
		return errPollerConfig
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errPollerConfig
	}
	return nil
}

func validateQueueSchema(table integrations.TinyTable) error {
	if table.ID != pollerTableID {
		return errQueueSchema
	}
	found := map[string]bool{}
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, column := range table.Columns {
		if column.ID == "" || column.Name == "" || ids[column.ID] || names[column.Name] {
			return errQueueSchema
		}
		ids[column.ID] = true
		names[column.Name] = true
		for _, name := range queueColumns {
			if column.Name == name {
				if column.Type != "text" {
					return errQueueSchema
				}
				found[name] = true
			}
		}
	}
	for _, name := range queueColumns {
		if !found[name] {
			return errQueueSchema
		}
	}
	return nil
}

type scopedTableSource interface {
	Table(context.Context) (integrations.TinyTable, error)
	Rows(context.Context, int, int) (integrations.TinyRowsPage, error)
	Ack(context.Context, string, integrations.TinyAcknowledgment) error
}
type schemaGuardedQueue struct{ source scopedTableSource }

func (q schemaGuardedQueue) Rows(ctx context.Context, offset, limit int) (integrations.TinyRowsPage, error) {
	if q.source == nil {
		return integrations.TinyRowsPage{}, errQueueSchema
	}
	table, err := q.source.Table(ctx)
	if err != nil || validateQueueSchema(table) != nil {
		return integrations.TinyRowsPage{}, errQueueSchema
	}
	return q.source.Rows(ctx, offset, limit)
}
func (q schemaGuardedQueue) Ack(ctx context.Context, rowID string, ack integrations.TinyAcknowledgment) error {
	if q.source == nil {
		return errQueueSchema
	}
	table, err := q.source.Table(ctx)
	if err != nil || validateQueueSchema(table) != nil {
		return errQueueSchema
	}
	return q.source.Ack(ctx, rowID, ack)
}
