package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
)

type Config struct {
	DemoEnabled                                                                                         bool
	AuthOrigin                                                                                          string
	Environment                                                                                         string
	DatabaseURL                                                                                         string `json:"-"`
	DatabaseIdentity, ProductionDatabaseIdentity, ListenAddress, OutboundMode, Simulator, RecipientMode string
}

func (c Config) Format(s fmt.State, verb rune) {
	fmt.Fprint(s, "Config{database:[REDACTED] outbound:off}")
}
func Load() (Config, error) { return FromEnv(os.Getenv) }
func FromEnv(get func(string) string) (Config, error) {
	c := Config{Environment: get("APP_ENV"), DatabaseURL: get("DATABASE_URL"), DatabaseIdentity: get("DATABASE_IDENTITY"), ProductionDatabaseIdentity: get("PRODUCTION_DATABASE_IDENTITY"), ListenAddress: get("LISTEN_ADDRESS"), OutboundMode: get("OUTBOUND_MODE"), Simulator: get("SIMULATOR"), RecipientMode: get("RECIPIENT_MODE")}
	fail := func(message string) (Config, error) { return Config{}, errors.New(message) }
	switch c.Environment {
	case "development", "staging", "production":
	default:
		return fail("APP_ENV must be development, staging or production")
	}
	if c.Environment != "development" {
		return fail("staging and production unavailable in local foundation")
	}
	u, e := url.Parse(c.DatabaseURL)
	if e != nil || u == nil {
		return fail("invalid database configuration")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return fail("invalid database scheme")
	}
	expectedDatabase := "osee_testops_dev"
	if get("CANDIDATE_PROFILE") == "fixture" {
		if get("AUTH_ORIGIN") != "http://127.0.0.1:8091" || get("DEMO_ENABLED") != "false" {
			return fail("candidate fixtures require the exact isolated origin and disabled demo")
		}
		expectedDatabase = "osee_testops_test"
	} else if get("CANDIDATE_PROFILE") != "" && get("CANDIDATE_PROFILE") != "local" {
		return fail("unknown candidate profile")
	}
	if u.Hostname() != "osee-testops-db" || u.Port() != "5432" || u.Path != "/"+expectedDatabase || c.DatabaseIdentity != expectedDatabase || u.RawQuery != "sslmode=disable" {
		return fail("database must be the isolated development fixture")
	}
	if c.ProductionDatabaseIdentity == c.DatabaseIdentity {
		return fail("production database identity forbidden")
	}
	if c.OutboundMode == "" {
		c.OutboundMode = "off"
	}
	if c.OutboundMode != "off" {
		return fail("outbound unavailable")
	}
	if c.Simulator != "" && c.Simulator != "labelled" {
		return fail("unknown simulator")
	}
	if c.RecipientMode != "" && c.RecipientMode != "test" {
		return fail("only test recipient mode available")
	}
	if c.ListenAddress == "" {
		c.ListenAddress = "127.0.0.1:8080"
	}
	_, listenPort, e := net.SplitHostPort(c.ListenAddress)
	if e != nil {
		return fail("invalid listen address")
	}
	c.AuthOrigin = get("AUTH_ORIGIN")
	if c.AuthOrigin == "" {
		c.AuthOrigin = "http://" + net.JoinHostPort("127.0.0.1", listenPort)
	}
	origin, e := url.Parse(c.AuthOrigin)
	if e != nil || origin == nil || origin.Scheme != "http" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.String() != c.AuthOrigin {
		return fail("AUTH_ORIGIN must be explicit local plain HTTP")
	}
	host, port, e := net.SplitHostPort(origin.Host)
	number, portError := strconv.Atoi(port)
	ip := net.ParseIP(host)
	if e != nil || portError != nil || number < 1 || number > 65535 || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
		return fail("AUTH_ORIGIN must use loopback and a valid port")
	}
	switch get("DEMO_ENABLED") {
	case "", "false":
	case "true":
		c.DemoEnabled = true
	default:
		return fail("DEMO_ENABLED must be true or false")
	}
	return c, nil
}
