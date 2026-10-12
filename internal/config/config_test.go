package config

import (
	"fmt"
	"strings"
	"testing"
)

func env(mode string) map[string]string {
	return map[string]string{"APP_ENV": mode, "DATABASE_URL": "postgres://fixture:private-password@osee-testops-db:5432/osee_testops_dev?sslmode=disable", "DATABASE_IDENTITY": "osee_testops_dev", "PRODUCTION_DATABASE_IDENTITY": "production", "OUTBOUND_MODE": "off", "RECIPIENT_MODE": "test"}
}
func load(m map[string]string) (Config, error) { return FromEnv(func(k string) string { return m[k] }) }
func TestProductionRejectsSimulators(t *testing.T) {
	m := env("production")
	m["SIMULATOR"] = "labelled"
	if _, e := load(m); e == nil {
		t.Fatal("production accepted simulator")
	}
}
func TestProductionRejectsUnsafeOutboundDefaults(t *testing.T) {
	for _, v := range []string{"", "live", "automatic"} {
		m := env("production")
		m["OUTBOUND_MODE"] = v
		if _, e := load(m); e == nil {
			t.Errorf("production accepted outbound %q", v)
		}
	}
}
func TestStagingRejectsProductionDatabaseIdentity(t *testing.T) {
	m := env("staging")
	m["PRODUCTION_DATABASE_IDENTITY"] = "osee_testops_dev"
	if _, e := load(m); e == nil {
		t.Fatal("staging accepted production identity")
	}
}
func TestUnknownEnvironmentRejected(t *testing.T) {
	for _, v := range []string{"", "prodution", "Production"} {
		if _, e := load(env(v)); e == nil {
			t.Errorf("accepted unknown environment %q", v)
		}
	}
}
func TestConfigFormattingRedactsDatabaseSecrets(t *testing.T) {
	c, e := load(env("development"))
	for _, f := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(f, c), "private-password") {
			t.Errorf("config formatting leaked password via %s", f)
		}
	}
	if e != nil && strings.Contains(e.Error(), "private-password") {
		t.Fatal("error leaked password")
	}
}
func TestDevelopmentOutboundOff(t *testing.T) {
	c, e := load(env("development"))
	if e != nil || c.OutboundMode != "off" {
		t.Fatal("development must load with outbound off")
	}
}
func TestNonDevelopmentFailsClosed(t *testing.T) {
	for _, mode := range []string{"staging", "production"} {
		if _, e := load(env(mode)); e == nil {
			t.Errorf("foundation must not enable %s runtime", mode)
		}
	}
}
