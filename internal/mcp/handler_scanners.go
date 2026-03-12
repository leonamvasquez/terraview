package mcp

import (
	"encoding/json"
	"log"
	"sort"

	"github.com/leonamvasquez/terraview/internal/scanner"
)

type scannerInfo struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
}

func handleScanners(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
	all := scanner.All()

	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]scannerInfo, 0, len(names))
	for _, name := range names {
		s := all[name]
		installed, _ := s.EnsureInstalled()
		info := scannerInfo{
			Name:      name,
			Installed: installed,
		}
		if installed {
			info.Version = s.Version()
		}
		result = append(result, info)
	}

	logger.Printf("[mcp:scanners] found %d scanners", len(result))
	return jsonResult(result)
}
