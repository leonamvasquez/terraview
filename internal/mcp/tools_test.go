package mcp

import (
	"encoding/json"
	"testing"
)

func TestAllTools_Returns11(t *testing.T) {
	tools := AllTools()
	if len(tools) != 11 {
		t.Fatalf("len(AllTools()) = %d, want 11", len(tools))
	}
}

func TestAllTools_UniqueNames(t *testing.T) {
	tools := AllTools()
	seen := make(map[string]bool)
	for _, tool := range tools {
		if seen[tool.Name] {
			t.Errorf("duplicate tool name: %q", tool.Name)
		}
		seen[tool.Name] = true
	}
}

func TestAllTools_ExpectedNames(t *testing.T) {
	expected := map[string]bool{
		"terraview_scan":            false,
		"terraview_explain":         false,
		"terraview_diagram":         false,
		"terraview_drift":           false,
		"terraview_history":         false,
		"terraview_history_trend":   false,
		"terraview_history_compare": false,
		"terraview_impact":          false,
		"terraview_cache":           false,
		"terraview_scanners":        false,
		"terraview_version":         false,
	}

	for _, tool := range AllTools() {
		if _, ok := expected[tool.Name]; ok {
			expected[tool.Name] = true
		} else {
			t.Errorf("unexpected tool: %q", tool.Name)
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("missing expected tool: %q", name)
		}
	}
}

func TestAllTools_ValidJSONSchema(t *testing.T) {
	for _, tool := range AllTools() {
		t.Run(tool.Name, func(t *testing.T) {
			if tool.Description == "" {
				t.Error("description should not be empty")
			}

			var schema map[string]interface{}
			if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
				t.Fatalf("invalid input schema JSON: %v", err)
			}

			typ, ok := schema["type"]
			if !ok || typ != "object" {
				t.Error("schema type should be 'object'")
			}

			props, ok := schema["properties"]
			if !ok {
				t.Error("schema should have 'properties'")
			}

			propsMap, ok := props.(map[string]interface{})
			if !ok {
				t.Error("properties should be an object")
			}

			// Most tools have dir property, but some (scanners, version, cache) may not
			noDir := map[string]bool{"terraview_scanners": true, "terraview_version": true, "terraview_cache": true}
			if !noDir[tool.Name] {
				if _, ok := propsMap["dir"]; !ok {
					t.Error("schema should have 'dir' property")
				}
			}
		})
	}
}

func TestLookupTool_Found(t *testing.T) {
	tool := LookupTool("terraview_scan")
	if tool == nil {
		t.Fatal("expected to find terraview_scan")
	}
	if tool.Name != "terraview_scan" {
		t.Errorf("name = %q, want %q", tool.Name, "terraview_scan")
	}
}

func TestLookupTool_NotFound(t *testing.T) {
	tool := LookupTool("nonexistent")
	if tool != nil {
		t.Error("expected nil for nonexistent tool")
	}
}

func TestAllTools_ScanHasScannerEnum(t *testing.T) {
	tool := LookupTool("terraview_scan")
	if tool == nil {
		t.Fatal("terraview_scan not found")
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
		t.Fatalf("invalid schema: %v", err)
	}

	props := schema["properties"].(map[string]interface{})
	scannerProp, ok := props["scanner"]
	if !ok {
		t.Fatal("scan tool should have 'scanner' property")
	}

	scannerMap := scannerProp.(map[string]interface{})
	enumRaw, ok := scannerMap["enum"]
	if !ok {
		t.Fatal("scanner property should have 'enum'")
	}

	enumList := enumRaw.([]interface{})
	if len(enumList) < 2 {
		t.Errorf("scanner enum has %d values, want at least 2", len(enumList))
	}
}

func TestAllTools_DriftHasIntelligence(t *testing.T) {
	tool := LookupTool("terraview_drift")
	if tool == nil {
		t.Fatal("terraview_drift not found")
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
		t.Fatalf("invalid schema: %v", err)
	}

	props := schema["properties"].(map[string]interface{})
	if _, ok := props["intelligence"]; !ok {
		t.Error("drift tool should have 'intelligence' property")
	}
}
