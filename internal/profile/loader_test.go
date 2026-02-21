package profile

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/config"
)

func TestLoad_ValidProfile(t *testing.T) {
	profiles := []string{"prod", "dev", "fintech", "startup"}
	for _, name := range profiles {
		p, err := Load(name)
		if err != nil {
			t.Errorf("Load(%q) failed: %v", name, err)
			continue
		}
		if p.Name == "" {
			t.Errorf("Load(%q): expected name, got empty", name)
		}
	}
}

func TestLoad_InvalidProfile(t *testing.T) {
	_, err := Load("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestLoad_CaseInsensitive(t *testing.T) {
	p, err := Load("PROD")
	if err != nil {
		t.Fatalf("Load(PROD) failed: %v", err)
	}
	if p == nil {
		t.Fatal("expected profile, got nil")
	}
}

func TestList(t *testing.T) {
	summaries, err := List()
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(summaries) < 4 {
		t.Errorf("expected at least 4 profiles, got %d", len(summaries))
	}
}

func TestApply_ScoringWeights(t *testing.T) {
	cfg := config.DefaultConfig()
	p := &Profile{
		Scoring: ScoringOverride{
			Weights: SeverityWeights{
				Critical: 20,
				High:     10,
				Medium:   5,
				Low:      1,
			},
		},
	}
	Apply(&cfg, p)
	if cfg.Scoring.SeverityWeights.Critical != 20 {
		t.Errorf("expected Critical=20, got %f", cfg.Scoring.SeverityWeights.Critical)
	}
}

func TestApply_RequiredTags(t *testing.T) {
	cfg := config.DefaultConfig()
	p := &Profile{
		RequiredTags: []string{"env", "owner"},
	}
	Apply(&cfg, p)
	if len(cfg.Rules.RequiredTags) != 2 {
		t.Errorf("expected 2 required tags, got %d", len(cfg.Rules.RequiredTags))
	}
}
