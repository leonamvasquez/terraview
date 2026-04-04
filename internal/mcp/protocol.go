// Package mcp implements a Model Context Protocol (MCP) server over stdio.
// It exposes terraview functionality as MCP tools that AI agents can call.
package mcp

import "encoding/json"

// JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Request is a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Result  interface{}      `json:"result,omitempty"`
	Error   *RPCError        `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error implements the error interface for RPCError.
func (e *RPCError) Error() string {
	return e.Message
}

// InitializeParams is sent by the client to start the session.
type InitializeParams struct {
	ProtocolVersion string      `json:"protocolVersion"`
	Capabilities    interface{} `json:"capabilities"`
	ClientInfo      MCPPeerInfo `json:"clientInfo"`
}

// MCPPeerInfo identifies a client or server.
type MCPPeerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeResult is returned after a successful handshake.
type InitializeResult struct {
	ProtocolVersion string      `json:"protocolVersion"`
	Capabilities    ServerCaps  `json:"capabilities"`
	ServerInfo      MCPPeerInfo `json:"serverInfo"`
}

// ServerCaps declares the server capabilities.
type ServerCaps struct {
	Tools *ToolsCap `json:"tools,omitempty"`
}

// ToolsCap indicates tool support.
type ToolsCap struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ToolsListResult wraps the tools/list response.
type ToolsListResult struct {
	Tools []ToolDef `json:"tools"`
}

// ToolAnnotations provides behavioral hints about a tool (MCP 2025-03+).
// Clients use these to decide how to present or gate tool calls.
type ToolAnnotations struct {
	// ReadOnlyHint indicates the tool does not modify any state.
	ReadOnlyHint bool `json:"readOnlyHint,omitempty"`
	// DestructiveHint indicates the tool may irreversibly delete or overwrite data.
	DestructiveHint bool `json:"destructiveHint,omitempty"`
	// IdempotentHint indicates calling the tool multiple times with the same args
	// produces the same result without additional side effects.
	IdempotentHint bool `json:"idempotentHint,omitempty"`
	// OpenWorldHint indicates the tool may interact with external systems (AI APIs,
	// cloud providers, package registries).
	OpenWorldHint bool `json:"openWorldHint,omitempty"`
}

// ToolDef defines a single MCP tool.
type ToolDef struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	InputSchema json.RawMessage  `json:"inputSchema"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
}

// ToolsCallParams contains the tools/call request parameters.
type ToolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolsCallResult is the response for tools/call.
type ToolsCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock is a text block in a tool result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ParseRequest attempts to parse a raw JSON line into a Request.
func ParseRequest(data []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	if req.JSONRPC != "2.0" {
		return nil, &RPCError{Code: CodeInvalidRequest, Message: "invalid jsonrpc version"}
	}
	return &req, nil
}

// NewResponse creates a successful JSON-RPC response.
func NewResponse(id *json.RawMessage, result interface{}) Response {
	return Response{JSONRPC: "2.0", ID: id, Result: result}
}

// NewErrorResponse creates a JSON-RPC error response.
func NewErrorResponse(id *json.RawMessage, code int, message string) Response {
	return Response{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: code, Message: message}}
}

// NewErrorResponseWithData creates a JSON-RPC error response with additional data.
func NewErrorResponseWithData(id *json.RawMessage, code int, message string, data interface{}) Response {
	return Response{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: code, Message: message, Data: data}}
}

// MarshalResponse serializes a response to JSON bytes.
func MarshalResponse(resp Response) ([]byte, error) {
	return json.Marshal(resp)
}
