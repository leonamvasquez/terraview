package mcp

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func newTestServer(input string) (*Server, *bytes.Buffer, *bytes.Buffer) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	logger := log.New(stderr, "[test] ", 0)
	reader := strings.NewReader(input)
	return NewServer("test-version", reader, stdout, logger), stdout, stderr
}

func parseResponses(t *testing.T, buf *bytes.Buffer) []map[string]interface{} {
	t.Helper()
	var responses []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("invalid JSON response line: %s\nerr: %v", line, err)
		}
		responses = append(responses, m)
	}
	return responses
}

func TestServer_Initialize(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}` + "\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	resp := responses[0]
	if resp["jsonrpc"] != "2.0" {
		t.Error("expected jsonrpc 2.0")
	}

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("expected result object")
	}
	serverInfo, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatal("expected serverInfo")
	}
	if serverInfo["name"] != "terraview" {
		t.Errorf("serverInfo.name = %q, want %q", serverInfo["name"], "terraview")
	}
	if serverInfo["version"] != "test-version" {
		t.Errorf("serverInfo.version = %q, want %q", serverInfo["version"], "test-version")
	}
}

func TestServer_ToolsList(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
`
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(responses))
	}

	// Second response is tools/list
	resp := responses[1]
	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("expected result object")
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatal("expected tools array")
	}
	if len(tools) != 4 {
		t.Errorf("expected 4 tools, got %d", len(tools))
	}
}

func TestServer_NotificationIgnored(t *testing.T) {
	// Notification has no id — server should not respond
	input := `{"jsonrpc":"2.0","method":"notifications/initialized"}
`
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	if stdout.Len() > 0 {
		t.Errorf("expected no output for notification, got: %s", stdout.String())
	}
}

func TestServer_UnknownMethod(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}
`
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	resp := responses[0]
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object")
	}
	if int(errObj["code"].(float64)) != CodeMethodNotFound {
		t.Errorf("error code = %v, want %d", errObj["code"], CodeMethodNotFound)
	}
}

func TestServer_MalformedJSON(t *testing.T) {
	input := "this is not json\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	resp := responses[0]
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object")
	}
	if int(errObj["code"].(float64)) != CodeParseError {
		t.Errorf("error code = %v, want %d", errObj["code"], CodeParseError)
	}
}

func TestServer_EOF(t *testing.T) {
	// Empty input simulates immediate EOF
	srv, _, _ := newTestServer("")
	if err := srv.Serve(); err != nil {
		t.Fatalf("serve should return nil on EOF, got: %v", err)
	}
}

func TestServer_EmptyLines(t *testing.T) {
	input := "\n\n\n"
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	if stdout.Len() > 0 {
		t.Errorf("expected no output for empty lines, got: %s", stdout.String())
	}
}

func TestServer_StdoutPurity(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}
`
	srv, stdout, stderr := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	// Every line on stdout must be valid JSON
	for i, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if line == "" {
			continue
		}
		if !json.Valid([]byte(line)) {
			t.Errorf("stdout line %d is not valid JSON: %s", i, line)
		}
	}

	// stderr should have log output
	if stderr.Len() == 0 {
		t.Error("expected logs on stderr")
	}
}

func TestServer_ToolsCallUnknownTool(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}
`
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	resp := responses[0]
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object")
	}
	if int(errObj["code"].(float64)) != CodeInvalidParams {
		t.Errorf("error code = %v, want %d", errObj["code"], CodeInvalidParams)
	}
}

func TestServer_ToolsCallInvalidParams(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"bad"}
`
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	resp := responses[0]
	errObj, ok := resp["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object for invalid params")
	}
	if int(errObj["code"].(float64)) != CodeInvalidParams {
		t.Errorf("error code = %v, want %d", errObj["code"], CodeInvalidParams)
	}
}

func TestServer_FullSequence(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"terraview_scan","arguments":{"dir":"/nonexistent"}}}
`
	srv, stdout, _ := newTestServer(input)

	if err := srv.Serve(); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	responses := parseResponses(t, stdout)
	// 3 responses: initialize, tools/list, tools/call (notification produces none)
	if len(responses) != 3 {
		t.Fatalf("expected 3 responses, got %d", len(responses))
	}

	// First: initialize
	r1 := responses[0]
	if _, ok := r1["result"]; !ok {
		t.Error("initialize should have result")
	}

	// Second: tools/list
	r2 := responses[1]
	result2, ok := r2["result"].(map[string]interface{})
	if !ok {
		t.Fatal("tools/list should have result")
	}
	tools := result2["tools"].([]interface{})
	if len(tools) != 4 {
		t.Errorf("expected 4 tools, got %d", len(tools))
	}

	// Third: tools/call for scan with nonexistent dir — should be tool error, not protocol error
	r3 := responses[2]
	result3, ok := r3["result"].(map[string]interface{})
	if !ok {
		t.Fatal("tools/call should have result (even for tool errors)")
	}
	if isErr, ok := result3["isError"]; ok && isErr == true {
		// Tool error — expected for nonexistent dir
		content := result3["content"].([]interface{})
		if len(content) == 0 {
			t.Error("tool error should have content")
		}
	}
}
