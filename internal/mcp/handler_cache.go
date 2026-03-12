package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/leonamvasquez/terraview/internal/aicache"
)

type cacheArgs struct {
	Action string `json:"action"`
}

type cacheStatusResponse struct {
	CacheDir   string     `json:"cache_dir"`
	Entries    int        `json:"entries"`
	TotalBytes int64      `json:"total_bytes"`
	Oldest     *time.Time `json:"oldest,omitempty"`
	Newest     *time.Time `json:"newest,omitempty"`
}

type cacheClearResponse struct {
	Status string `json:"status"`
}

func handleCache(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
	var args cacheArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return ToolsCallResult{}, fmt.Errorf("invalid arguments: %w", err)
		}
	}

	action := args.Action
	if action == "" {
		action = "status"
	}

	cacheDir := aicache.DiskCacheDir()

	switch action {
	case "status":
		entries, totalSize, oldest, newest, err := aicache.DiskStats(cacheDir)
		if err != nil {
			return ToolsCallResult{}, fmt.Errorf("cache stats: %w", err)
		}

		resp := cacheStatusResponse{
			CacheDir:   cacheDir,
			Entries:    entries,
			TotalBytes: totalSize,
		}
		if !oldest.IsZero() {
			resp.Oldest = &oldest
		}
		if !newest.IsZero() {
			resp.Newest = &newest
		}

		logger.Printf("[mcp:cache] status: %d entries, %d bytes", entries, totalSize)
		return jsonResult(resp)

	case "clear":
		if err := aicache.ClearDisk(cacheDir); err != nil {
			return ToolsCallResult{}, fmt.Errorf("cache clear: %w", err)
		}
		logger.Printf("[mcp:cache] cleared cache at %s", cacheDir)
		return jsonResult(cacheClearResponse{Status: "cleared"})

	default:
		return ToolsCallResult{}, fmt.Errorf("unknown action %q (valid: status, clear)", action)
	}
}
