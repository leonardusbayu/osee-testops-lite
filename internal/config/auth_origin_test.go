package config

import "testing"

func TestAuthOriginDefaultsToLocalListenPort(t *testing.T) {
	values := env("development")
	values["LISTEN_ADDRESS"] = "127.0.0.1:8087"
	config, err := load(values)
	if err != nil || config.AuthOrigin != "http://127.0.0.1:8087" {
		t.Fatal("origin did not match explicit local listener")
	}
}
func TestAuthOriginAcceptsExplicitLoopbackPublishedPort(t *testing.T) {
	values := env("development")
	values["LISTEN_ADDRESS"] = "0.0.0.0:8080"
	values["AUTH_ORIGIN"] = "http://127.0.0.1:8090"
	config, err := load(values)
	if err != nil || config.AuthOrigin != values["AUTH_ORIGIN"] || config.OutboundMode != "off" {
		t.Fatal("published loopback origin was not preserved safely")
	}
}
func TestAuthOriginRejectsUnsafeOrUnsupportedDeployment(t *testing.T) {
	for _, origin := range []string{"http://0.0.0.0:8090", "http://192.0.2.1:8090", "http://example.invalid:8090", "https://127.0.0.1:8090", "http://user@127.0.0.1:8090", "http://127.0.0.1:8090/", "http://127.0.0.1:8090?mode=test", "http://127.0.0.1:8090#fragment", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:port"} {
		values := env("development")
		values["AUTH_ORIGIN"] = origin
		if _, err := load(values); err == nil {
			t.Errorf("unsafe deployment origin accepted: %q", origin)
		}
	}
}
