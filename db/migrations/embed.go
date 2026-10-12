package migrations

import _ "embed"

//go:embed 001_core.up.sql
var Core string

//go:embed 002_auth.up.sql
var Auth string

//go:embed 003_development_fixture.up.sql
var DevelopmentFixture string

//go:embed 004_sessions.up.sql
var Sessions string

//go:embed 005_intake.up.sql
var Intake string

//go:embed 008_staff_identity.up.sql
var StaffIdentity string
