package mcp

import (
	"encoding/json"
	"log"
	"runtime"
)

type versionResponse struct {
	Version         string `json:"version"`
	ProtocolVersion string `json:"protocol_version"`
	GoVersion       string `json:"go_version"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
}

func handleVersion(_ json.RawMessage, logger *log.Logger, serverVersion string) (ToolsCallResult, error) {
	resp := versionResponse{
		Version:         serverVersion,
		ProtocolVersion: "2025-06-18",
		GoVersion:       runtime.Version(),
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
	}

	logger.Printf("[mcp:version] %s", serverVersion)
	return jsonResult(resp)
}
