// dartsync synchronizes a bounded operational exception with a durable local
// mapping. Credentials and provider responses are never printed.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"osee-testops-lite/internal/config"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/integrations"
)

func main() {
	operation := flag.String("operation", "read", "sync, reconcile, read")
	tokenPath := flag.String("token-file", ".local/integrations/dart-token", "local credential file")
	inputPath := flag.String("input", "", "bounded exception JSON file")
	outputPath := flag.String("output", ".local/integrations/dart-sync-receipt.json", "safe synchronization receipt file")
	board := flag.String("board", "osee.co.id TestOps/Tasks", "exact observed Dart board title")
	id := flag.String("id", "", "canonical exception UUID for read or reconcile")
	openStatus := flag.String("open-status", "To-do", "exact observed open status")
	doingStatus := flag.String("doing-status", "Doing", "exact observed in progress status")
	doneStatus := flag.String("done-status", "Done", "exact observed completed status")
	staging := flag.Bool("staging", true, "label remote task as synthetic STAGING fixture")
	flag.Parse()
	if *operation != "sync" && *operation != "reconcile" && *operation != "read" {
		fail("unsupported operation")
	}
	cfg, err := config.Load()
	if err != nil {
		fail("isolated local database configuration required")
	}
	credential, err := os.ReadFile(*tokenPath)
	if err != nil || len(credential) > 65536 {
		fail("Dart credential file unavailable")
	}
	client, err := integrations.NewDartMCP(strings.TrimRight(string(credential), "\r\n"), nil)
	if err != nil {
		fail("Dart credential invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	store, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		fail("isolated local database unavailable")
	}
	defer store.Close()
	if err = store.Migrate(ctx); err != nil {
		fail("local synchronization migration unavailable")
	}
	service, err := integrations.NewDartSynchronizer(store, client, integrations.DartSyncConfig{Dartboard: *board, Statuses: map[string]string{"open": *openStatus, "in_progress": *doingStatus, "done": *doneStatus}, Staging: *staging})
	if err != nil {
		fail("operational mapping configuration invalid")
	}
	var receipt integrations.DartSyncReceipt
	if *operation == "sync" {
		input, e := readInput(*inputPath)
		if e != nil {
			fail("bounded exception specification required")
		}
		receipt, err = service.Sync(ctx, input)
	} else {
		exception, e := core.ParseID(*id)
		if e != nil {
			fail("canonical exception UUID required")
		}
		if *operation == "reconcile" {
			receipt, err = service.Reconcile(ctx, exception)
		} else {
			receipt, err = service.Read(ctx, exception)
		}
	}
	encoded, e := json.Marshal(receipt)
	if e != nil {
		fail("receipt encoding unavailable")
	}
	if e = os.WriteFile(*outputPath, append(encoded, '\n'), 0600); e != nil {
		fail("safe receipt file unavailable; read durable mapping before retry")
	}
	fmt.Println(string(encoded))
	if err != nil {
		fail("synchronization did not complete; retain durable state and reconcile before retry")
	}
}

func readInput(path string) (integrations.DartSyncInput, error) {
	var input integrations.DartSyncInput
	if path == "" {
		return input, fmt.Errorf("missing input")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		return input, fmt.Errorf("invalid input")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&input); err != nil {
		return input, fmt.Errorf("invalid exception JSON")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return input, fmt.Errorf("trailing exception data")
	}
	return input, nil
}
func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
