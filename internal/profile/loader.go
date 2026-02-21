package profile

import (
	"embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/leonamvasquez/terraview/internal/config"
)

//go:embed profiles/*.yaml
var profilesFS embed.FS

// Profile defines a review profile with scoring and rule overrides.
type Profile struct {
	Name          string          `yaml:"name"`
	Description   string          `yaml:"description"`
	StrictMode    *bool           `yaml:"strict_mode,omitempty"`
	Scoring       ScoringOverride `yaml:"scoring"`
	RequiredTags  []string        `yaml:"required_tags,omitempty"`
	DisabledRules []string        `yaml:"disabled_rules,omitempty"`
	EnabledRules  []string        `yaml:"enabled_rules,omitempty"`
}

// ScoringOverride allows a profile to override severity weights.
type ScoringOverride struct {
	Weights SeverityWeights `yaml:"weights"`
}

// SeverityWeights maps severity levels to numeric weights.
type SeverityWeights struct {
	Critical float64 `yaml:"critical"`
	High     float64 `yaml:"high"`
	Medium   float64 `yaml:"medium"`
	Low      float64 `yaml:"low"`
}

// ProfileSummary is a brief representation for listing profiles.
type ProfileSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Load reads and parses a named profile from the embedded profiles directory.
func Load(name string) (*Profile, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	filename := fmt.Sprintf("profiles/%s.yaml", normalized)

	data, err := profilesFS.ReadFile(filename)
	if err != nil {
		available, _ := List()
		names := make([]string, len(available))
		for i, p := range available {
			names[i] = p.Name
		}
		return nil, fmt.Errorf("profile %q not found. Available: %s", name, strings.Join(names, ", "))
	}

	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse profile %q: %w", name, err)
	}

	if p.Name == "" {
		p.Name = normalized
	}

	return &p, nil
}

// List returns all available profile summaries.
func List() ([]ProfileSummary, error) {
	entries, err := profilesFS.ReadDir("profiles")
	if err != nil {
		return nil, fmt.Errorf("failed to read profiles directory: %w", err)
	}

	var summaries []ProfileSummary
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		data, err := profilesFS.ReadFile("profiles/" + entry.Name())
		if err != nil {
			continue
		}

		var p Profile
		if err := yaml.Unmarshal(data, &p); err != nil {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".yaml")
		if p.Name == "" {
			p.Name = name
		}

		summaries = append(summaries, ProfileSummary{
			Name:        p.Name,
			Description: p.Description,
		})
	}

	return summaries, nil
}

// Apply modifies the config based on the profile settings.
func Apply(cfg *config.Config, p *Profile) {
	if p.Scoring.Weights.Critical > 0 {
		cfg.Scoring.SeverityWeights.Critical = p.Scoring.Weights.Critical
	}
	if p.Scoring.Weights.High > 0 {
		cfg.Scoring.SeverityWeights.High = p.Scoring.Weights.High
	}
	if p.Scoring.Weights.Medium > 0 {
		cfg.Scoring.SeverityWeights.Medium = p.Scoring.Weights.Medium
	}
	if p.Scoring.Weights.Low > 0 {
		cfg.Scoring.SeverityWeights.Low = p.Scoring.Weights.Low
	}

	if len(p.RequiredTags) > 0 {
		cfg.Rules.RequiredTags = p.RequiredTags
	}
}
