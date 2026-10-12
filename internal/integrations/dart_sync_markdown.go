package integrations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Normalize only the single backslash-underscore escape observed in Dart's
// Markdown descriptions. Multiple backslashes stay literal; applying general
// Markdown rendering or repeated unescaping would weaken ownership checks.
func normalizeDartMarkdown(value string) string {
	var normalized strings.Builder
	normalized.Grow(len(value))
	for i := 0; i < len(value); {
		if value[i] != '\\' {
			normalized.WriteByte(value[i])
			i++
			continue
		}
		start := i
		for i < len(value) && value[i] == '\\' {
			i++
		}
		if i-start == 1 && i < len(value) && value[i] == '_' {
			normalized.WriteByte('_')
			i++
			continue
		}
		normalized.WriteString(value[start:i])
	}
	return normalized.String()
}

func canResumeReadOnlyHold(row syncRow, remote DartTask) bool {
	if row.external == "" || row.appliedVersion < 1 || row.appliedVersion >= row.version || len(row.appliedHash) != 64 || (row.unresolved && row.intentRecorded) {
		return false
	}
	// Match the exact canonical fields generated when applied_hash was stored.
	// Provider metadata, such as creator, tags or default priority, is not part
	// of the controlled operational task projection.
	applied := DartTask{Title: remote.Title, Dartboard: remote.Dartboard, Description: normalizeDartMarkdown(remote.Description), Status: remote.Status, DueAt: remote.DueAt, Assignees: []string{}}
	encoded, err := json.Marshal(applied)
	if err != nil {
		return false
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]) == row.appliedHash
}
