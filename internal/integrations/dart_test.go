package integrations_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"osee-testops-lite/internal/integrations"
	"strings"
	"testing"
)

type dartTransport func(*http.Request) (*http.Response, error)

func (f dartTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func dartResponse(contentType, body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{contentType}, "Mcp-Session-Id": []string{"fixture-session"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestDartUsesNegotiatedSessionAndSSE(t *testing.T) {
	var methods []string
	client, e := integrations.NewDartMCP("dsa_synthetic_only", dartTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://mcp.dartai.com/mcp" || r.Header.Get("Authorization") != "Bearer dsa_synthetic_only" || r.Header.Get("Accept") != "application/json, text/event-stream" {
			t.Fatal("wrong target or transport")
		}
		var request struct {
			Method string
			ID     int
			Params map[string]any
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Fatal("invalid RPC")
		}
		methods = append(methods, request.Method)
		switch request.Method {
		case "initialize":
			return dartResponse("application/json", `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`), nil
		case "notifications/initialized":
			if r.Header.Get("Mcp-Session-Id") != "fixture-session" || r.Header.Get("MCP-Protocol-Version") != "2025-06-18" {
				t.Fatal("session not forwarded")
			}
			return &http.Response{StatusCode: 202, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		case "tools/call":
			if request.Params["name"] != "list_tasks" {
				t.Fatal("wrong tool")
			}
			return dartResponse("text/event-stream", `event: message
data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}

event: message
data: {"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"results":[{"id":"abcdefghijkl","title":"fixture"}]}}}

`), nil
		}
		t.Fatal("unexpected method")
		return nil, nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	result, e := client.Tasks(context.Background(), "osee.co.id TestOps")
	if e != nil || !strings.Contains(string(result), "abcdefghijkl") {
		t.Fatalf("SSE tasks failed: %v", e)
	}
	if strings.Join(methods, ",") != "initialize,notifications/initialized,tools/call" {
		t.Fatal("wrong lifecycle")
	}
	if strings.Contains(fmt.Sprintf("%+v", client), "synthetic_only") {
		t.Fatal("credential leaked")
	}
}

func TestDartMutationIsNotRetriedAfterUncertainOutcome(t *testing.T) {
	calls := 0
	c, _ := integrations.NewDartMCP("dsa_synthetic_only", dartTransport(func(r *http.Request) (*http.Response, error) {
		var request struct {
			Method string
			ID     int
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		switch request.Method {
		case "initialize":
			return dartResponse("application/json", `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`), nil
		case "notifications/initialized":
			return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(""))}, nil
		default:
			calls++
			return nil, io.ErrUnexpectedEOF
		}
	}))
	_, e := c.CreateTask(context.Background(), integrations.DartTask{Title: "synthetic exception", Dartboard: "osee.co.id TestOps", Description: "Synthetic receipt only"})
	if e != integrations.ErrDartAmbiguous || calls != 1 {
		t.Fatalf("mutation retried or uncertainty hidden: %v calls=%d", e, calls)
	}
}

func TestDartRejectsRedirectsAndAuthFailures(t *testing.T) {
	for _, status := range []int{302, 401, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			c, _ := integrations.NewDartMCP("dsa_synthetic_only", dartTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://untrusted.example/"}}, Body: io.NopCloser(strings.NewReader("private error body"))}, nil
			}))
			_, e := c.Configuration(context.Background())
			if e != integrations.ErrDartUnavailable || calls != 1 || strings.Contains(e.Error(), "private") {
				t.Fatal("unsafe failure handling")
			}
		})
	}
}

func TestDartMalformedMutationResultRequiresReconciliation(t *testing.T) {
	for _, result := range []string{`{"isError":true}`, `{}`, `{"content":[{"type":"text","text":"not JSON"}]}`, `[]`} {
		t.Run(result, func(t *testing.T) {
			mutations := 0
			client, _ := integrations.NewDartMCP("dsa_synthetic_only", dartTransport(func(r *http.Request) (*http.Response, error) {
				var request struct {
					Method string
					ID     int
				}
				_ = json.NewDecoder(r.Body).Decode(&request)
				switch request.Method {
				case "initialize":
					return dartResponse("application/json", `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`), nil
				case "notifications/initialized":
					return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(""))}, nil
				default:
					mutations++
					return dartResponse("application/json", fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":%s}`, request.ID, result)), nil
				}
			}))
			_, err := client.CreateTask(context.Background(), integrations.DartTask{Title: "STAGING exception", Dartboard: "osee.co.id TestOps/Tasks"})
			if err != integrations.ErrDartAmbiguous || mutations != 1 {
				t.Fatalf("unsafe mutation failure: %v, calls=%d", err, mutations)
			}
		})
	}
}
