package config

import "testing"

func candidateFixtureEnv() map[string]string {
	m := env("development")
	m["DATABASE_URL"] = "postgres://fixture:***@osee-testops-db:5432/osee_testops_test?sslmode=disable"
	m["DATABASE_IDENTITY"] = "osee_testops_test"
	m["AUTH_ORIGIN"] = "http://127.0.0.1:8091"
	m["DEMO_ENABLED"] = "false"
	m["CANDIDATE_PROFILE"] = "fixture"
	return m
}

func TestCandidateFixtureUsesOnlyPrivateTestDatabase(t *testing.T) {
	c, err := load(candidateFixtureEnv())
	if err != nil || c.DatabaseIdentity != "osee_testops_test" {
		t.Fatal("explicit candidate fixture database was refused")
	}
}

func TestCandidateFixtureRejectsOtherOriginsModesAndDatabaseIdentities(t *testing.T) {
	cases := []struct{ key, value string }{
		{"AUTH_ORIGIN", "http://127.0.0.1:8090"}, {"AUTH_ORIGIN", "http://0.0.0.0:8091"},
		{"CANDIDATE_PROFILE", ""}, {"CANDIDATE_PROFILE", "local"}, {"CANDIDATE_PROFILE", "production"},
		{"APP_ENV", "staging"}, {"OUTBOUND_MODE", "live"}, {"DEMO_ENABLED", "true"},
		{"DATABASE_IDENTITY", "osee_testops_dev"},
		{"DATABASE_URL", "postgres://fixture:***@osee-testops-db:5432/osee_testops_dev?sslmode=disable"},
	}
	for _, item := range cases {
		t.Run(item.key+"="+item.value, func(t *testing.T) {
			m := candidateFixtureEnv()
			m[item.key] = item.value
			if _, err := load(m); err == nil {
				t.Fatal("unsafe fixture configuration accepted")
			}
		})
	}
}
