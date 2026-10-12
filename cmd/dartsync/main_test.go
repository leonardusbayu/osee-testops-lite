package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExceptionInputRejectsUnknownAndTrailingData(t *testing.T) {
	for name, body := range map[string]string{"unknown": `{"exception_id":"00000000-0000-0000-0000-000000000000","email":"private@example.invalid"}`, "trailing": `{"source_version":1} {"source_version":2}`} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "exception.json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readInput(path); err == nil {
				t.Fatal("unexpected exception data accepted")
			}
		})
	}
}
