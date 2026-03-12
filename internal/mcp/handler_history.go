package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/leonamvasquez/terraview/internal/history"
)

// --- terraview_history ---

type historyArgs struct {
	Dir   string `json:"dir"`
	Limit int    `json:"limit"`
	Since string `json:"since"`
}

func handleHistory(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
	var args historyArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return ToolsCallResult{}, fmt.Errorf("invalid arguments: %w", err)
		}
	}

	dir := args.Dir
	if dir == "" {
		dir = "."
	}

	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("open history db: %w", err)
	}
	defer store.Close()

	filter := history.ListFilter{
		ProjectHash: history.ProjectHash(dir),
		Limit:       args.Limit,
	}
	if filter.Limit <= 0 {
		filter.Limit = 10
	}

	if args.Since != "" {
		t, err := time.Parse("2006-01-02", args.Since)
		if err != nil {
			return ToolsCallResult{}, fmt.Errorf("invalid since date (use YYYY-MM-DD): %w", err)
		}
		filter.Since = t
	}

	records, err := store.List(filter)
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("list history: %w", err)
	}

	logger.Printf("[mcp:history] dir=%q records=%d", dir, len(records))
	return jsonResult(records)
}

// --- terraview_history_trend ---

type historyTrendArgs struct {
	Dir   string `json:"dir"`
	Limit int    `json:"limit"`
}

func handleHistoryTrend(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
	var args historyTrendArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return ToolsCallResult{}, fmt.Errorf("invalid arguments: %w", err)
		}
	}

	dir := args.Dir
	if dir == "" {
		dir = "."
	}

	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("open history db: %w", err)
	}
	defer store.Close()

	limit := args.Limit
	if limit <= 0 {
		limit = 20
	}

	records, err := store.List(history.ListFilter{
		ProjectHash: history.ProjectHash(dir),
		Limit:       limit,
	})
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("list history: %w", err)
	}

	if len(records) < 2 {
		return ToolsCallResult{}, fmt.Errorf("need at least 2 scan records for trend analysis, found %d", len(records))
	}

	trends := history.ComputeTrendsFromRecords(records)
	logger.Printf("[mcp:history_trend] dir=%q records=%d trends=%d", dir, len(records), len(trends))
	return jsonResult(trends)
}

// --- terraview_history_compare ---

type historyCompareArgs struct {
	Dir    string `json:"dir"`
	Before int64  `json:"before"`
	After  int64  `json:"after"`
}

func handleHistoryCompare(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
	var args historyCompareArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return ToolsCallResult{}, fmt.Errorf("invalid arguments: %w", err)
		}
	}

	dir := args.Dir
	if dir == "" {
		dir = "."
	}

	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("open history db: %w", err)
	}
	defer store.Close()

	projectHash := history.ProjectHash(dir)

	// If before/after are 0, use the two most recent scans
	if args.Before == 0 && args.After == 0 {
		records, err := store.List(history.ListFilter{
			ProjectHash: projectHash,
			Limit:       2,
		})
		if err != nil {
			return ToolsCallResult{}, fmt.Errorf("list history: %w", err)
		}
		if len(records) < 2 {
			return ToolsCallResult{}, fmt.Errorf("need at least 2 scan records to compare, found %d", len(records))
		}
		// records[0] is newest, records[1] is older
		result := history.CompareTwoScans("latest", records[1], records[0])
		logger.Printf("[mcp:history_compare] compared latest 2 scans for %s", dir)
		return jsonResult(result)
	}

	// Fetch specific scans by ID
	allRecords, err := store.List(history.ListFilter{
		ProjectHash: projectHash,
		Limit:       1000,
	})
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("list history: %w", err)
	}

	var oldScan, newScan *history.ScanRecord
	for i := range allRecords {
		if allRecords[i].ID == args.Before {
			oldScan = &allRecords[i]
		}
		if allRecords[i].ID == args.After {
			newScan = &allRecords[i]
		}
	}

	if oldScan == nil {
		return ToolsCallResult{}, fmt.Errorf("scan ID %d not found", args.Before)
	}
	if newScan == nil {
		return ToolsCallResult{}, fmt.Errorf("scan ID %d not found", args.After)
	}

	result := history.CompareTwoScans("compare", *oldScan, *newScan)
	logger.Printf("[mcp:history_compare] compared scan %d vs %d", args.Before, args.After)
	return jsonResult(result)
}
