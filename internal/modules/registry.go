package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	registryBaseURL = "https://registry.terraform.io/v1/modules"
	registryTimeout = 10 * time.Second
)

// registryResponse is the subset of the Terraform Registry API response we need.
type registryResponse struct {
	Version string `json:"version"`
}

// TerraformRegistry checks module versions against the Terraform Registry API.
type TerraformRegistry struct {
	client  *http.Client
	baseURL string
}

// NewTerraformRegistry creates a registry checker with default settings.
func NewTerraformRegistry() *TerraformRegistry {
	return &TerraformRegistry{
		client:  &http.Client{Timeout: registryTimeout},
		baseURL: registryBaseURL,
	}
}

// LatestVersion returns the latest published version for a registry module.
func (r *TerraformRegistry) LatestVersion(namespace, name, provider string) (string, error) {
	url := fmt.Sprintf("%s/%s/%s/%s", r.baseURL, namespace, name, provider)

	ctx, cancel := context.WithTimeout(context.Background(), registryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("registry request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("registry fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry returned %d for %s/%s/%s", resp.StatusCode, namespace, name, provider)
	}

	var result registryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("registry decode: %w", err)
	}

	return result.Version, nil
}
