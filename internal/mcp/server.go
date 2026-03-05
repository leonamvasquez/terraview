package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
)

// Server is a Model Context Protocol server that communicates over stdio.
type Server struct {
	version string
	reader  io.Reader
	writer  io.Writer
	logger  *log.Logger
}

// NewServer creates an MCP server. All JSON-RPC output goes to w; logs go to logger.
func NewServer(version string, r io.Reader, w io.Writer, logger *log.Logger) *Server {
	return &Server{
		version: version,
		reader:  r,
		writer:  w,
		logger:  logger,
	}
}

// Serve reads JSON-RPC messages from the reader and dispatches them.
// It returns nil on EOF.
func (s *Server) Serve() error {
	scanner := bufio.NewScanner(s.reader)
	// Allow large messages (up to 10 MB)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		req, err := ParseRequest(line)
		if err != nil {
			// Parse error — send error response with null id
			s.send(NewErrorResponse(nil, CodeParseError, "parse error: "+err.Error()))
			continue
		}

		// Notifications have no id — no response expected
		if req.ID == nil {
			s.handleNotification(req)
			continue
		}

		resp := s.dispatch(req)
		s.send(resp)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stdin read error: %w", err)
	}
	return nil
}

func (s *Server) handleNotification(req *Request) {
	switch req.Method {
	case "notifications/initialized":
		s.logger.Println("client initialized")
	default:
		s.logger.Printf("unknown notification: %s", req.Method)
	}
}

func (s *Server) dispatch(req *Request) Response {
	s.logger.Printf("← %s", req.Method)
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	default:
		return NewErrorResponse(req.ID, CodeMethodNotFound, "method not found: "+req.Method)
	}
}

func (s *Server) handleInitialize(req *Request) Response {
	result := InitializeResult{
		ProtocolVersion: "2025-06-18",
		Capabilities: ServerCaps{
			Tools: &ToolsCap{},
		},
		ServerInfo: MCPPeerInfo{
			Name:    "terraview",
			Version: s.version,
		},
	}
	return NewResponse(req.ID, result)
}

func (s *Server) handleToolsList(req *Request) Response {
	return NewResponse(req.ID, ToolsListResult{Tools: AllTools()})
}

func (s *Server) handleToolsCall(req *Request) Response {
	var params ToolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return NewErrorResponse(req.ID, CodeInvalidParams, "invalid params: "+err.Error())
	}

	tool := LookupTool(params.Name)
	if tool == nil {
		return NewErrorResponse(req.ID, CodeInvalidParams, "unknown tool: "+params.Name)
	}

	s.logger.Printf("tools/call: %s", params.Name)

	var result ToolsCallResult
	var err error

	switch params.Name {
	case "terraview_scan":
		result, err = handleScan(params.Arguments, s.logger)
	case "terraview_explain":
		result, err = handleExplain(params.Arguments, s.logger)
	case "terraview_diagram":
		result, err = handleDiagram(params.Arguments, s.logger)
	case "terraview_drift":
		result, err = handleDrift(params.Arguments, s.logger)
	default:
		return NewErrorResponse(req.ID, CodeInvalidParams, "unknown tool: "+params.Name)
	}

	if err != nil {
		// Tool errors are returned as content with isError=true, not JSON-RPC errors.
		// This follows MCP spec: tool execution errors are tool-level, not protocol-level.
		result = ToolsCallResult{
			Content: []ContentBlock{{Type: "text", Text: err.Error()}},
			IsError: true,
		}
	}

	return NewResponse(req.ID, result)
}

func (s *Server) send(resp Response) {
	data, err := MarshalResponse(resp)
	if err != nil {
		s.logger.Printf("marshal error: %v", err)
		return
	}
	fmt.Fprintf(s.writer, "%s\n", data)
}
