package migrations

import _ "embed"

//go:embed 006_integrations.up.sql
var Integrations string
