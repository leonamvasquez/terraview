package mcp

import (
	"encoding/json"
	"testing"
)

func TestParseRequest_Valid(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	req, err := ParseRequest(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "initialize" {
		t.Errorf("method = %q, want %q", req.Method, "initialize")
	}
	if req.ID == nil {
		t.Fatal("expected non-nil ID")
	}
}

func TestParseRequest_Notification(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	req, err := ParseRequest(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.ID != nil {
		t.Error("expected nil ID for notification")
	}
	if req.Method != "notifications/initialized" {
		t.Errorf("method = %q, want %q", req.Method, "notifications/initialized")
	}
}

func TestParseRequest_ToolsList(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	req, err := ParseRequest(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "tools/list" {
		t.Errorf("method = %q, want %q", req.Method, "tools/list")
	}
}

func TestParseRequest_ToolsCall(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"terraview_scan","arguments":{"dir":"/tmp"}}}`)
	req, err := ParseRequest(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "tools/call" {
		t.Errorf("method = %q, want %q", req.Method, "tools/call")
	}
	if req.Params == nil {
		t.Fatal("expected non-nil params")
	}
}

func TestParseRequest_Malformed(t *testing.T) {
	raw := []byte(`{this is not json}`)
	_, err := ParseRequest(raw)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseRequest_InvalidVersion(t *testing.T) {
	raw := []byte(`{"jsonrpc":"1.0","id":1,"method":"initialize"}`)
	_, err := ParseRequest(raw)
	if err == nil {
		t.Fatal("expected error for invalid jsonrpc version")
	}
	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("expected *RPCError, got %T", err)
	}
	if rpcErr.Code != CodeInvalidRequest {
		t.Errorf("code = %d, want %d", rpcErr.Code, CodeInvalidRequest)
	}
}

func TestNewResponse(t *testing.T) {
	id := json.RawMessage(`1`)
	resp := NewResponse(&id, map[string]string{"key": "value"})
	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want %q", resp.JSONRPC, "2.0")
	}
	if resp.Error != nil {
		t.Error("expected nil error")
	}
	if resp.Result == nil {
		t.Error("expected non-nil result")
	}
}

func TestNewErrorResponse(t *testing.T) {
	id := json.RawMessage(`42`)
	resp := NewErrorResponse(&id, CodeMethodNotFound, "not found")
	if resp.Error == nil {
		t.Fatal("expected non-nil error")
	}
	if resp.Error.Code != CodeMethodNotFound {
		t.Errorf("code = %d, want %d", resp.Error.Code, CodeMethodNotFound)
	}
	if resp.Error.Message != "not found" {
		t.Errorf("message = %q, want %q", resp.Error.Message, "not found")
	}
	if resp.Result != nil {
		t.Error("expected nil result")
	}
}

func TestNewErrorResponseWithData(t *testing.T) {
	id := json.RawMessage(`99`)
	resp := NewErrorResponseWithData(&id, CodeInternalError, "boom", map[string]string{"detail": "stack trace"})
	if resp.Error == nil {
		t.Fatal("expected non-nil error")
	}
	if resp.Error.Code != CodeInternalError {
		t.Errorf("code = %d, want %d", resp.Error.Code, CodeInternalError)
	}
	if resp.Error.Data == nil {
		t.Error("expected non-nil error data")
	}
}

func TestMarshalResponse_Success(t *testing.T) {
	id := json.RawMessage(`1`)
	resp := NewResponse(&id, "ok")
	data, err := MarshalResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want %q", parsed["jsonrpc"], "2.0")
	}
	if parsed["result"] != "ok" {
		t.Errorf("result = %v, want %q", parsed["result"], "ok")
	}
}

func TestMarshalResponse_Error(t *testing.T) {
	id := json.RawMessage(`2`)
	resp := NewErrorResponse(&id, CodeParseError, "parse error")
	data, err := MarshalResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	errObj, ok := parsed["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object")
	}
	if errObj["code"].(float64) != float64(CodeParseError) {
		t.Errorf("error code = %v, want %d", errObj["code"], CodeParseError)
	}
}

func TestRPCError_ImplementsError(t *testing.T) {
	var err error = &RPCError{Code: CodeInternalError, Message: "test error"}
	if err.Error() != "test error" {
		t.Errorf("Error() = %q, want %q", err.Error(), "test error")
	}
}

func TestParseRequest_NullID(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":null,"method":"initialize"}`)
	req, err := ParseRequest(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With omitempty, json.Unmarshal treats explicit null as nil pointer
	// This is expected behavior — null id is treated like a notification
	if req.ID != nil {
		t.Errorf("expected nil ID for null, got %s", string(*req.ID))
	}
}
