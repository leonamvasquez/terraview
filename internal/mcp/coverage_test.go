package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// --- extractResourceType ---

func TestExtractResourceType_WithDot(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"aws_s3_bucket.my_bucket", "aws_s3_bucket"},
		{"aws_instance.web", "aws_instance"},
		{"google_compute_instance.main", "google_compute_instance"},
		{"module.vpc.aws_vpc.this", "module"},
	}
	for _, tc := range tests {
		got := extractResourceType(tc.addr)
		if got != tc.want {
			t.Errorf("extractResourceType(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestExtractResourceType_NoDot(t *testing.T) {
	// When addr has no dot, should return addr as-is
	got := extractResourceType("nodot")
	if got != "nodot" {
		t.Errorf("extractResourceType(\"nodot\") = %q, want %q", got, "nodot")
	}
}

func TestExtractResourceType_Empty(t *testing.T) {
	got := extractResourceType("")
	if got != "" {
		t.Errorf("extractResourceType(\"\") = %q, want %q", got, "")
	}
}

// --- jsonResult ---

func TestJsonResult_Struct(t *testing.T) {
	type sample struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	result, err := jsonResult(sample{Name: "test", Value: 42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content")
	}
	if result.Content[0].Type != "text" {
		t.Errorf("type = %q, want %q", result.Content[0].Type, "text")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed["name"] != "test" {
		t.Errorf("name = %v, want %q", parsed["name"], "test")
	}
}

func TestJsonResult_Map(t *testing.T) {
	m := map[string]string{"key": "value"}
	result, err := jsonResult(m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Content[0].Text == "" {
		t.Error("expected non-empty JSON text")
	}
}

// --- buildExplainPrompt ---

func TestBuildExplainPrompt_ContainsRequiredSections(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_s3_bucket.logs", Type: "aws_s3_bucket", Action: "create"},
		{Address: "aws_instance.web", Type: "aws_instance", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	prompt := buildExplainPrompt(resources, graph)

	checks := []string{
		"You are a senior cloud architect",
		"aws_s3_bucket.logs",
		"aws_instance.web",
		"TOPOLOGY:",
		"RESOURCES:",
		"findings",
		"summary",
	}

	for _, check := range checks {
		if !strings.Contains(prompt, check) {
			t.Errorf("prompt does not contain %q", check)
		}
	}
}

func TestBuildExplainPrompt_Empty(t *testing.T) {
	resources := []parser.NormalizedResource{}
	graph := topology.BuildGraph(resources)

	prompt := buildExplainPrompt(resources, graph)
	if prompt == "" {
		t.Error("expected non-empty prompt even for empty resources")
	}
	if !strings.Contains(prompt, "TOPOLOGY:") {
		t.Error("expected TOPOLOGY section in prompt")
	}
}

// --- handleCache with invalid JSON ---

func TestHandleCache_InvalidJSON(t *testing.T) {
	args := json.RawMessage(`{not valid json}`)
	_, err := handleCache(args, testLogger())
	if err == nil {
		t.Error("expected error for invalid JSON args")
	}
}

// --- handleFixSuggest validation path ---

func TestHandleFixSuggest_MissingRequiredArgs(t *testing.T) {
	// Missing rule_id, resource, message — should return validation error
	args, _ := json.Marshal(map[string]string{
		"dir": t.TempDir(),
	})
	_, err := handleFixSuggest(json.RawMessage(args), testLogger())
	if err == nil {
		t.Error("expected error when required args are missing")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("expected 'required' in error, got: %v", err)
	}
}

func TestHandleFixSuggest_InvalidJSON(t *testing.T) {
	args := json.RawMessage(`{not valid json}`)
	_, err := handleFixSuggest(args, testLogger())
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestHandleFixSuggest_NoProviderConfigured(t *testing.T) {
	// Use temp HOME so no real config is found
	t.Setenv("HOME", t.TempDir())

	args, _ := json.Marshal(map[string]string{
		"dir":      t.TempDir(),
		"rule_id":  "CKV_AWS_18",
		"resource": "aws_s3_bucket.logs",
		"message":  "S3 bucket access logging not enabled",
	})

	_, err := handleFixSuggest(json.RawMessage(args), testLogger())
	if err == nil {
		t.Error("expected error when no AI provider is configured")
	}
}

// --- server.go: send with failing writer ---

// failWriter always returns an error on Write to force MarshalResponse path
// and reach the marshal error branch.
// Note: MarshalResponse itself rarely fails with standard types, so we use a
// writer that fails to cover the fmt.Fprintf path instead, triggering the
// logger path when send encounters a write error.
type failWriter struct{}

func (failWriter) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("simulated write error")
}

func TestServer_SendWriteError(t *testing.T) {
	// A write error should NOT panic; the server logs and continues.
	stderr := &bytes.Buffer{}
	logger := log.New(stderr, "[test] ", 0)
	srv := NewServer("v1", strings.NewReader(""), &failWriter{}, logger)

	id := json.RawMessage(`1`)
	resp := NewResponse(&id, map[string]string{"k": "v"})
	// send must not panic even when the underlying writer fails
	srv.send(resp)
}

// --- server.go: handleNotification with unknown method ---

func TestServer_UnknownNotification(t *testing.T) {
	// A notification (no id) with an unknown method should NOT produce output.
	input := `{"jsonrpc":"2.0","method":"unknown/notification"}` + "\n"
	srv, stdout, stderr := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	// No response expected for notifications
	if stdout.Len() > 0 {
		t.Errorf("expected no output for unknown notification, got: %s", stdout.String())
	}
	// But there should be a log entry
	if !strings.Contains(stderr.String(), "unknown notification") {
		t.Errorf("expected log for unknown notification, stderr: %s", stderr.String())
	}
}

// --- server.go: message larger than initial 64KB buffer ---

func TestServer_LargeMessage(t *testing.T) {
	// Build a message larger than scannerBufSize (64KB) but within maxMessageSize (10MB).
	// Pad the method name with a long params value.
	bigValue := strings.Repeat("x", 100*1024) // 100 KB
	msg := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"},"extra":%q}}`,
		bigValue,
	)
	input := msg + "\n"

	srv, stdout, _ := newTestServer(input)
	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	// Should be a successful initialize response (extra unknown field is ignored)
	resp := responses[0]
	if _, ok := resp["result"]; !ok {
		t.Errorf("expected result in response, got: %v", resp)
	}
}

// --- server.go: batch message (array) should produce parse error ---

func TestServer_BatchMessageProducesParseError(t *testing.T) {
	// JSON arrays are not valid JSON-RPC 2.0 requests (batch not supported).
	// ParseRequest will fail since it expects a single object.
	input := `[{"jsonrpc":"2.0","id":1,"method":"initialize"}]` + "\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 error response for batch, got %d", len(responses))
	}
	errObj, ok := responses[0]["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object for batch request")
	}
	if int(errObj["code"].(float64)) != CodeParseError {
		t.Errorf("error code = %v, want %d (ParseError)", errObj["code"], CodeParseError)
	}
}

// --- server.go: Serve returns error on scanner read error ---

// errorReader simulates a Read that returns data then a non-EOF error.
type errorAfterReader struct {
	data    []byte
	pos     int
	errOnce bool
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	if r.pos < len(r.data) {
		n := copy(p, r.data[r.pos:])
		r.pos += n
		return n, nil
	}
	if !r.errOnce {
		r.errOnce = true
		return 0, fmt.Errorf("simulated read error")
	}
	return 0, io.EOF
}

func TestServer_ServeReturnsReadError(t *testing.T) {
	// bufio.Scanner wraps the reader error — Serve should return a non-nil error.
	data := "not complete line"
	r := &errorAfterReader{data: []byte(data)}
	stdout := &bytes.Buffer{}
	logger := log.New(io.Discard, "", 0)
	srv := NewServer("v1", r, stdout, logger)

	err := srv.Serve()
	if err == nil {
		t.Error("expected non-nil error when reader fails mid-stream")
	}
}

// --- handler_common.go: jsonResult with unmarshalable value ---

// channelValue is a value that json.Marshal cannot serialize.
type channelValue struct {
	Ch chan int
}

func TestJsonResult_UnmarshalableValue(t *testing.T) {
	_, err := jsonResult(channelValue{Ch: make(chan int)})
	if err == nil {
		t.Error("expected error for unmarshalable value")
	}
}

// --- handleCache: clear action ---

func TestHandleCache_ClearAction(t *testing.T) {
	// Override HOME so the cache dir is in a temp location.
	t.Setenv("HOME", t.TempDir())

	args := json.RawMessage(`{"action":"clear"}`)
	result, err := handleCache(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["status"] != "cleared" {
		t.Errorf("status = %v, want %q", parsed["status"], "cleared")
	}
}

// --- handleHistoryCompare: path with specific before/after IDs ---

func TestHandleHistoryCompare_SpecificIDsNotFound(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Pass non-zero before/after IDs that don't exist in an empty DB.
	args, _ := json.Marshal(map[string]interface{}{
		"dir":    "/tmp/nonexistent-project",
		"before": 100,
		"after":  200,
	})

	_, err := handleHistoryCompare(json.RawMessage(args), testLogger())
	if err == nil {
		t.Error("expected error when scan IDs are not found")
	}
}

func TestHandleHistoryCompare_InvalidJSON(t *testing.T) {
	args := json.RawMessage(`{not valid}`)
	_, err := handleHistoryCompare(args, testLogger())
	if err == nil {
		t.Error("expected error for invalid JSON args")
	}
}

// --- handleHistoryTrend: invalid JSON ---

func TestHandleHistoryTrend_InvalidJSON(t *testing.T) {
	args := json.RawMessage(`{not valid}`)
	_, err := handleHistoryTrend(args, testLogger())
	if err == nil {
		t.Error("expected error for invalid JSON args")
	}
}

// --- handleHistory: invalid JSON ---

func TestHandleHistory_InvalidJSON(t *testing.T) {
	args := json.RawMessage(`{not valid}`)
	_, err := handleHistory(args, testLogger())
	if err == nil {
		t.Error("expected error for invalid JSON args")
	}
}

// --- handleToolsCall: tool that succeeds via server dispatch ---

func TestServer_ToolsCallVersion(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"terraview_version","arguments":{}}}` + "\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	result, ok := responses[0]["result"].(map[string]interface{})
	if !ok {
		t.Fatal("expected result object")
	}
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("expected content array")
	}
}

func TestServer_ToolsCallScanners(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"terraview_scanners","arguments":{}}}` + "\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	if _, ok := responses[0]["result"]; !ok {
		t.Error("expected result in response")
	}
}

func TestServer_ToolsCallCache(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"terraview_cache","arguments":{"action":"clear"}}}` + "\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	if _, ok := responses[0]["result"]; !ok {
		t.Error("expected result in response")
	}
}

func TestServer_ToolsCallHistory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"terraview_history","arguments":{"dir":"/tmp/nonexistent"}}}` + "\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	if _, ok := responses[0]["result"]; !ok {
		t.Error("expected result in response")
	}
}

func TestServer_ToolsCallHistoryTrend(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"terraview_history_trend","arguments":{"dir":"/tmp/nonexistent"}}}` + "\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	// Tool error is expected (not enough records), but protocol-level should have result not error
	if _, ok := responses[0]["result"]; !ok {
		t.Error("expected result (tool-level error wrapped in result), not protocol error")
	}
}

func TestServer_ToolsCallHistoryCompare(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"terraview_history_compare","arguments":{"dir":"/tmp/nonexistent"}}}` + "\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	if _, ok := responses[0]["result"]; !ok {
		t.Error("expected result in response")
	}
}

func TestServer_ToolsCallFixSuggestMissingArgs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Missing required args — tool returns error content, not protocol error
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"terraview_fix_suggest","arguments":{"dir":"."}}}` + "\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	result, ok := responses[0]["result"].(map[string]interface{})
	if !ok {
		t.Fatal("expected result object (tool errors are wrapped, not protocol errors)")
	}
	if result["isError"] != true {
		t.Error("expected isError=true for missing required args")
	}
}
