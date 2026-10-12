package config

import "testing"

func TestDemoConfigurationIsOptInAndStrict(t *testing.T) {
	values := env("development")
	c, err := load(values)
	if err != nil || c.DemoEnabled {
		t.Fatal("demo must default off")
	}
	values["DEMO_ENABLED"] = "true"
	c, err = load(values)
	if err != nil || !c.DemoEnabled {
		t.Error("explicit dev demo not enabled")
	}
	for _, value := range []string{"1", "yes", "TRUE", "unknown"} {
		values["DEMO_ENABLED"] = value
		if _, err := load(values); err == nil {
			t.Errorf("ambiguous demo setting accepted: %s", value)
		}
	}
	values["DEMO_ENABLED"] = "false"
	c, err = load(values)
	if err != nil || c.DemoEnabled {
		t.Error("explicit off ignored")
	}
}
func TestDemoConfigurationRejectsNonLocalAndNonDev(t *testing.T) {
	for _, mode := range []string{"staging", "production"} {
		values := env(mode)
		values["DEMO_ENABLED"] = "true"
		if _, err := load(values); err == nil {
			t.Error("demo enabled outside development")
		}
	}
	values := env("development")
	values["DEMO_ENABLED"] = "true"
	values["AUTH_ORIGIN"] = "http://192.0.2.1:8090"
	if _, err := load(values); err == nil {
		t.Error("demo exposed on non-loopback origin")
	}
}
