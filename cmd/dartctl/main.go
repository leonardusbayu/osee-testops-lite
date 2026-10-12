// dartctl exercises the narrow internal Dart adapter with local configuration
// files. It never accepts a credential on the command line or writes it to logs.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"osee-testops-lite/internal/integrations"
	"time"
)

func main() {
	operation := flag.String("operation", "config", "config, list, create, update, get")
	tokenPath := flag.String("token-file", ".local/integrations/dart-token", "local credential file")
	inputPath := flag.String("input", "", "task specification file")
	outputPath := flag.String("output", ".local/integrations/dart-result.json", "local result file")
	board := flag.String("board", "osee.co.id TestOps/Tasks", "exact observed Dart board title")
	id := flag.String("id", "", "mapped Dart task ID")
	flag.Parse()
	credential, e := os.ReadFile(*tokenPath)
	if e != nil {
		fail("Dart credential file unavailable")
	}
	client, e := integrations.NewDartMCP(string(bytesTrim(credential)), nil)
	if e != nil {
		fail("Dart credential invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var result json.RawMessage
	switch *operation {
	case "config":
		result, e = client.Configuration(ctx)
	case "list":
		result, e = client.Tasks(ctx, *board)
	case "get":
		result, e = client.Task(ctx, *id)
	case "create", "update":
		if *inputPath == "" {
			fail("task specification required")
		}
		input, err := os.ReadFile(*inputPath)
		if err != nil || len(input) > 65536 {
			fail("invalid task specification")
		}
		var task integrations.DartTask
		if json.Unmarshal(input, &task) != nil {
			fail("invalid task JSON")
		}
		if task.Dartboard != *board {
			fail("task board does not match configured board")
		}
		if *operation == "create" {
			result, e = client.CreateTask(ctx, task)
		} else {
			result, e = client.UpdateTask(ctx, *id, task)
		}
	default:
		fail("unsupported operation")
	}
	if e != nil {
		if e == integrations.ErrDartAmbiguous {
			fail("mutation outcome uncertain; reconcile before retry")
		}
		fail("Dart request failed; secret and response omitted")
	}
	if e = os.WriteFile(*outputPath, result, 0600); e != nil {
		fail("result file unavailable")
	}
	var object map[string]any
	_ = json.Unmarshal(result, &object)
	summary := map[string]any{"operation": *operation, "succeeded": true, "output": *outputPath}
	for _, key := range []string{"id", "title", "status", "dartboard"} {
		if value, ok := object[key]; ok {
			summary[key] = value
		}
	}
	encoded, _ := json.Marshal(summary)
	fmt.Println(string(encoded))
}
func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
