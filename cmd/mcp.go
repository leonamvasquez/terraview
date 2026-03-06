package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/mcp"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Model Context Protocol (MCP) server",
	Long: `MCP server for AI agent integration.

Exposes terraview functionality via the Model Context Protocol,
allowing AI agents (Claude Code, Cursor, Windsurf) to call
terraview tools programmatically over stdio.

Usage:
  terraview mcp serve`,
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server over stdio",
	Long: `Starts a Model Context Protocol server that reads JSON-RPC 2.0
messages from stdin and writes responses to stdout.

Logs go to stderr. Only valid JSON-RPC appears on stdout.

Register with Claude Code:
  claude mcp add terraview -- terraview mcp serve

Register with Cursor (.cursor/mcp.json):
  {
    "mcpServers": {
      "terraview": {
        "command": "terraview",
        "args": ["mcp", "serve"]
      }
    }
  }

Tools exposed:
  terraview_scan      Security scan with scorecard
  terraview_explain   AI infrastructure explanation
  terraview_diagram   ASCII infrastructure diagram
  terraview_drift     Drift detection and classification`,
	RunE: runMCPServe,
}

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
	rootCmd.AddCommand(mcpCmd)
}

func runMCPServe(cmd *cobra.Command, args []string) error {
	logger := log.New(os.Stderr, "[mcp] ", log.LstdFlags)
	logger.Println("starting MCP server")

	server := mcp.NewServer(Version, os.Stdin, os.Stdout, logger)
	return server.Serve()
}
