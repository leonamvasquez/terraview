package modules

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTerraformRegistry_LatestVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hashicorp/consul/aws" {
			http.NotFound(w, r)
			return
		}
		resp := registryResponse{Version: "0.12.0"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer server.Close()

	reg := &TerraformRegistry{
		client:  server.Client(),
		baseURL: server.URL,
	}

	version, err := reg.LatestVersion("hashicorp", "consul", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "0.12.0" {
		t.Errorf("expected version 0.12.0, got %q", version)
	}
}

func TestTerraformRegistry_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	reg := &TerraformRegistry{
		client:  server.Client(),
		baseURL: server.URL,
	}

	_, err := reg.LatestVersion("nonexistent", "module", "aws")
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestTerraformRegistry_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json")) //nolint:errcheck
	}))
	defer server.Close()

	reg := &TerraformRegistry{
		client:  server.Client(),
		baseURL: server.URL,
	}

	_, err := reg.LatestVersion("hashicorp", "consul", "aws")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
