package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const dartEndpoint = "https://mcp.dartai.com/mcp"
const maxDartResponse = 2 << 20

var ErrDartUnavailable = errors.New("Dart MCP unavailable; retain operation for reconciliation")
var ErrDartAmbiguous = errors.New("Dart mutation outcome uncertain; reconcile before retry")

// DartMCP is an internal operations adapter. It never exposes agent, delete,
// attachment, or arbitrary tools to a participant-facing assistant.
type DartMCP struct {
	mu               sync.Mutex
	token            string
	http             *http.Client
	session, version string
	sequence         int64
}

type DartTask struct {
	Title       string   `json:"title"`
	Dartboard   string   `json:"dartboard"`
	Description string   `json:"description"`
	Status      string   `json:"status,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Priority    string   `json:"priority,omitempty"`
	DueAt       string   `json:"dueAt,omitempty"`
	Assignees   []string `json:"assignees"`
}

func NewDartMCP(token string, transport http.RoundTripper) (*DartMCP, error) {
	if !strings.HasPrefix(token, "dsa_") || strings.ContainsAny(token, "\r\n\t ") || len(token) < 12 {
		return nil, errors.New("invalid Dart credential")
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &DartMCP{token: token, http: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (d *DartMCP) Format(s fmt.State, verb rune) { fmt.Fprint(s, "DartMCP{credential:[REDACTED]}") }

type dartRPC struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}
type dartReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

func (d *DartMCP) rpc(ctx context.Context, method string, params any, notification bool) (json.RawMessage, error) {
	id := int64(0)
	if !notification {
		d.sequence++
		id = d.sequence
	}
	body, e := json.Marshal(dartRPC{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if e != nil {
		return nil, ErrDartUnavailable
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, dartEndpoint, bytes.NewReader(body))
	if e != nil {
		return nil, ErrDartUnavailable
	}
	r.Header.Set("Authorization", "Bearer "+d.token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if d.session != "" {
		r.Header.Set("Mcp-Session-Id", d.session)
	}
	if d.version != "" {
		r.Header.Set("MCP-Protocol-Version", d.version)
	}
	response, e := d.http.Do(r)
	if e != nil {
		return nil, ErrDartUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == 404 {
		d.session = ""
		d.version = ""
		return nil, ErrDartUnavailable
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, ErrDartUnavailable
	}
	if notification {
		if response.StatusCode != 202 {
			return nil, ErrDartUnavailable
		}
		return nil, nil
	}
	if method == "initialize" {
		d.session = response.Header.Get("Mcp-Session-Id")
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, maxDartResponse+1))
	if e != nil || len(data) > maxDartResponse {
		return nil, ErrDartUnavailable
	}
	decode := func(raw []byte) (json.RawMessage, error) {
		var v dartReply
		if json.Unmarshal(raw, &v) != nil || v.JSONRPC != "2.0" || v.ID != id || len(v.Error) > 0 && string(v.Error) != "null" || len(v.Result) == 0 {
			return nil, ErrDartUnavailable
		}
		return v.Result, nil
	}
	if strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		return decode(data)
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		return nil, ErrDartUnavailable
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxDartResponse)
	var lines []string
	consume := func() (json.RawMessage, error) {
		if len(lines) == 0 {
			return nil, nil
		}
		payload := []byte(strings.Join(lines, "\n"))
		lines = nil
		var v dartReply
		if json.Unmarshal(payload, &v) != nil {
			return nil, ErrDartUnavailable
		}
		if v.ID != id {
			return nil, nil
		}
		return decode(payload)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if raw, e := consume(); e != nil || raw != nil {
				return raw, e
			}
		} else if strings.HasPrefix(line, "data:") {
			lines = append(lines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if scanner.Err() != nil {
		return nil, ErrDartUnavailable
	}
	if raw, e := consume(); raw != nil || e != nil {
		return raw, e
	}
	return nil, ErrDartUnavailable
}

func (d *DartMCP) initialize(ctx context.Context) error {
	if d.version != "" {
		return nil
	}
	r, e := d.rpc(ctx, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "osee.co.id TestOps bridge", "version": "2.0"}}, false)
	if e != nil {
		return e
	}
	var v struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(r, &v) != nil {
		return ErrDartUnavailable
	}
	switch v.ProtocolVersion {
	case "2025-03-26", "2025-06-18", "2025-11-25":
		d.version = v.ProtocolVersion
	default:
		return ErrDartUnavailable
	}
	_, e = d.rpc(ctx, "notifications/initialized", map[string]any{}, true)
	if e != nil {
		d.version = ""
	}
	return e
}

func (d *DartMCP) call(ctx context.Context, name string, args any, mutation bool) (json.RawMessage, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.initialize(ctx); e != nil {
		return nil, e
	}
	r, e := d.rpc(ctx, "tools/call", map[string]any{"name": name, "arguments": args}, false)
	if e != nil {
		if mutation {
			return nil, ErrDartAmbiguous
		}
		return nil, e
	}
	// A provider may have committed a mutation even when its tool result is
	// malformed or reports an error. Once dispatched, reconcile before retrying.
	resultFailure := ErrDartUnavailable
	if mutation {
		resultFailure = ErrDartAmbiguous
	}
	var tool struct {
		IsError    bool            `json:"isError"`
		Structured json.RawMessage `json:"structuredContent"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(r, &tool) != nil {
		return nil, resultFailure
	}
	if tool.IsError {
		return nil, resultFailure
	}
	if len(tool.Structured) > 0 && string(tool.Structured) != "null" {
		return tool.Structured, nil
	}
	for _, c := range tool.Content {
		if c.Type == "text" && json.Valid([]byte(c.Text)) {
			return json.RawMessage(c.Text), nil
		}
	}
	return nil, resultFailure
}

func (d *DartMCP) Configuration(ctx context.Context) (json.RawMessage, error) {
	return d.call(ctx, "get_config", map[string]any{}, false)
}
func (d *DartMCP) Tasks(ctx context.Context, board string) (json.RawMessage, error) {
	if board == "" {
		return nil, errors.New("Dart board required")
	}
	return d.call(ctx, "list_tasks", map[string]any{"dartboard": board, "limit": 100, "no_defaults": true}, false)
}
func (d *DartMCP) Task(ctx context.Context, id string) (json.RawMessage, error) {
	if !dartID(id) {
		return nil, errors.New("invalid Dart task ID")
	}
	return d.call(ctx, "get_task", map[string]string{"id": id}, false)
}
func (d *DartMCP) CreateTask(ctx context.Context, task DartTask) (json.RawMessage, error) {
	if task.Title == "" || len(task.Title) > 240 || task.Dartboard == "" || len(task.Description) > 10000 {
		return nil, errors.New("invalid operational task")
	}
	if task.Assignees == nil {
		task.Assignees = []string{}
	}
	return d.call(ctx, "create_task", map[string]any{"item": task}, true)
}
func (d *DartMCP) UpdateTask(ctx context.Context, id string, task DartTask) (json.RawMessage, error) {
	if !dartID(id) || task.Dartboard == "" || task.Title == "" || len(task.Description) > 10000 {
		return nil, errors.New("invalid operational task update")
	}
	b, _ := json.Marshal(task)
	var item map[string]any
	_ = json.Unmarshal(b, &item)
	item["id"] = id
	return d.call(ctx, "update_task", map[string]any{"id": id, "item": item}, true)
}
func dartID(id string) bool {
	if len(id) != 12 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
