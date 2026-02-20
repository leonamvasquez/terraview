package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const configFileName = ".terraview.yaml"

// Config represents the full .terraview.yaml configuration.
type Config struct {
	LLM     LLMConfig     `yaml:"llm"`
	Scoring ScoringConfig `yaml:"scoring"`
	Rules   RulesConfig   `yaml:"rules"`
	Output  OutputConfig  `yaml:"output"`
}

// LLMConfig configures LLM behavior.
type LLMConfig struct {
	Enabled        bool         `yaml:"enabled"`
	Provider       string       `yaml:"provider"`
	Model          string       `yaml:"model"`
	URL            string       `yaml:"url"`
	APIKey         string       `yaml:"api_key"`
	TimeoutSeconds int          `yaml:"timeout_seconds"`
	Temperature    float64      `yaml:"temperature"`
	Ollama         OllamaConfig `yaml:"ollama"`
}

// OllamaConfig holds Ollama-specific resource limits.
type OllamaConfig struct {
	MaxThreads      int `yaml:"max_threads"`
	MaxMemoryMB     int `yaml:"max_memory_mb"`
	MinFreeMemoryMB int `yaml:"min_free_memory_mb"`
}

// ScoringConfig allows overriding severity weights.
type ScoringConfig struct {
	SeverityWeights SeverityWeightsConfig `yaml:"severity_weights"`
}

// SeverityWeightsConfig holds per-severity weight overrides.
type SeverityWeightsConfig struct {
	Critical float64 `yaml:"critical"`
	High     float64 `yaml:"high"`
	Medium   float64 `yaml:"medium"`
	Low      float64 `yaml:"low"`
}

// RulesConfig configures rule loading.
type RulesConfig struct {
	RequiredTags []string `yaml:"required_tags"`
	RulePacks    []string `yaml:"rule_packs"`
}

// OutputConfig configures output defaults.
type OutputConfig struct {
	Format string `yaml:"format"` // "pretty" (default), "compact", "json"
}

// DefaultConfig returns the default configuration with sensible values.
func DefaultConfig() Config {
	return Config{
		LLM: LLMConfig{
			Enabled:        true,
			Provider:       "ollama",
			Model:          "llama3.1:8b",
			URL:            "http://localhost:11434",
			TimeoutSeconds: 120,
			Temperature:    0.2,
			Ollama: OllamaConfig{
				MaxThreads:      0, // 0 = use all CPUs
				MaxMemoryMB:     0, // 0 = no limit
				MinFreeMemoryMB: 1024,
			},
		},
		Scoring: ScoringConfig{
			SeverityWeights: SeverityWeightsConfig{
				Critical: 5.0,
				High:     3.0,
				Medium:   1.0,
				Low:      0.5,
			},
		},
		Rules: RulesConfig{
			RequiredTags: nil,
			RulePacks:    nil,
		},
		Output: OutputConfig{
			Format: "pretty",
		},
	}
}

// Load reads .terraview.yaml from the given workspace directory.
// If the file does not exist, returns DefaultConfig with no error.
// If the file exists but is invalid, returns an error.
func Load(workDir string) (Config, error) {
	cfg := DefaultConfig()

	configPath := filepath.Join(workDir, configFileName)
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("failed to read %s: %w", configPath, err)
	}

	var fileCfg fileConfig
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return cfg, fmt.Errorf("failed to parse %s: %w", configPath, err)
	}

	if err := fileCfg.validate(); err != nil {
		return cfg, fmt.Errorf("invalid %s: %w", configPath, err)
	}

	cfg = fileCfg.merge(cfg)
	return cfg, nil
}

// fileConfig is the raw parsed YAML before validation and merging.
type fileConfig struct {
	LLM     *fileLLMConfig     `yaml:"llm"`
	Scoring *fileScoringConfig `yaml:"scoring"`
	Rules   *fileRulesConfig   `yaml:"rules"`
	Output  *fileOutputConfig  `yaml:"output"`
}

type fileLLMConfig struct {
	Enabled        *bool            `yaml:"enabled"`
	Provider       *string          `yaml:"provider"`
	Model          *string          `yaml:"model"`
	URL            *string          `yaml:"url"`
	APIKey         *string          `yaml:"api_key"`
	TimeoutSeconds *int             `yaml:"timeout_seconds"`
	Temperature    *float64         `yaml:"temperature"`
	Ollama         *fileOllamaConfig `yaml:"ollama"`
}

type fileOllamaConfig struct {
	MaxThreads      *int `yaml:"max_threads"`
	MaxMemoryMB     *int `yaml:"max_memory_mb"`
	MinFreeMemoryMB *int `yaml:"min_free_memory_mb"`
}

type fileScoringConfig struct {
	SeverityWeights *fileSeverityWeights `yaml:"severity_weights"`
}

type fileSeverityWeights struct {
	Critical *float64 `yaml:"critical"`
	High     *float64 `yaml:"high"`
	Medium   *float64 `yaml:"medium"`
	Low      *float64 `yaml:"low"`
}

type fileRulesConfig struct {
	RequiredTags *[]string `yaml:"required_tags"`
	RulePacks    *[]string `yaml:"rule_packs"`
}

type fileOutputConfig struct {
	Format *string `yaml:"format"`
}

// validate checks constraints on the parsed config.
func (f *fileConfig) validate() error {
	if f.LLM != nil {
		if f.LLM.Temperature != nil {
			t := *f.LLM.Temperature
			if t < 0.0 || t > 1.0 {
				return fmt.Errorf("llm.temperature must be between 0.0 and 1.0, got %.2f", t)
			}
		}
		if f.LLM.TimeoutSeconds != nil && *f.LLM.TimeoutSeconds <= 0 {
			return fmt.Errorf("llm.timeout_seconds must be positive, got %d", *f.LLM.TimeoutSeconds)
		}
		if f.LLM.Ollama != nil {
			if f.LLM.Ollama.MaxThreads != nil && *f.LLM.Ollama.MaxThreads < 0 {
				return fmt.Errorf("llm.ollama.max_threads must be >= 0")
			}
			if f.LLM.Ollama.MaxMemoryMB != nil && *f.LLM.Ollama.MaxMemoryMB < 0 {
				return fmt.Errorf("llm.ollama.max_memory_mb must be >= 0")
			}
			if f.LLM.Ollama.MinFreeMemoryMB != nil && *f.LLM.Ollama.MinFreeMemoryMB < 0 {
				return fmt.Errorf("llm.ollama.min_free_memory_mb must be >= 0")
			}
		}
	}

	if f.Scoring != nil && f.Scoring.SeverityWeights != nil {
		sw := f.Scoring.SeverityWeights
		if sw.Critical != nil && *sw.Critical < 0 {
			return fmt.Errorf("scoring.severity_weights.critical must be >= 0")
		}
		if sw.High != nil && *sw.High < 0 {
			return fmt.Errorf("scoring.severity_weights.high must be >= 0")
		}
		if sw.Medium != nil && *sw.Medium < 0 {
			return fmt.Errorf("scoring.severity_weights.medium must be >= 0")
		}
		if sw.Low != nil && *sw.Low < 0 {
			return fmt.Errorf("scoring.severity_weights.low must be >= 0")
		}
	}

	if f.Output != nil && f.Output.Format != nil {
		switch *f.Output.Format {
		case "pretty", "compact", "json":
			// valid
		default:
			return fmt.Errorf("output.format must be pretty, compact, or json, got %q", *f.Output.Format)
		}
	}

	return nil
}

// merge applies file values over defaults. Only non-nil fields override.
func (f *fileConfig) merge(defaults Config) Config {
	cfg := defaults

	if f.LLM != nil {
		if f.LLM.Enabled != nil {
			cfg.LLM.Enabled = *f.LLM.Enabled
		}
		if f.LLM.Provider != nil && *f.LLM.Provider != "" {
			cfg.LLM.Provider = *f.LLM.Provider
		}
		if f.LLM.Model != nil && *f.LLM.Model != "" {
			cfg.LLM.Model = *f.LLM.Model
		}
		if f.LLM.URL != nil && *f.LLM.URL != "" {
			cfg.LLM.URL = *f.LLM.URL
		}
		if f.LLM.APIKey != nil && *f.LLM.APIKey != "" {
			cfg.LLM.APIKey = *f.LLM.APIKey
		}
		if f.LLM.TimeoutSeconds != nil {
			cfg.LLM.TimeoutSeconds = *f.LLM.TimeoutSeconds
		}
		if f.LLM.Temperature != nil {
			cfg.LLM.Temperature = *f.LLM.Temperature
		}
		if f.LLM.Ollama != nil {
			if f.LLM.Ollama.MaxThreads != nil {
				cfg.LLM.Ollama.MaxThreads = *f.LLM.Ollama.MaxThreads
			}
			if f.LLM.Ollama.MaxMemoryMB != nil {
				cfg.LLM.Ollama.MaxMemoryMB = *f.LLM.Ollama.MaxMemoryMB
			}
			if f.LLM.Ollama.MinFreeMemoryMB != nil {
				cfg.LLM.Ollama.MinFreeMemoryMB = *f.LLM.Ollama.MinFreeMemoryMB
			}
		}
	}

	if f.Scoring != nil && f.Scoring.SeverityWeights != nil {
		sw := f.Scoring.SeverityWeights
		if sw.Critical != nil {
			cfg.Scoring.SeverityWeights.Critical = *sw.Critical
		}
		if sw.High != nil {
			cfg.Scoring.SeverityWeights.High = *sw.High
		}
		if sw.Medium != nil {
			cfg.Scoring.SeverityWeights.Medium = *sw.Medium
		}
		if sw.Low != nil {
			cfg.Scoring.SeverityWeights.Low = *sw.Low
		}
	}

	if f.Rules != nil {
		if f.Rules.RequiredTags != nil {
			cfg.Rules.RequiredTags = *f.Rules.RequiredTags
		}
		if f.Rules.RulePacks != nil {
			cfg.Rules.RulePacks = *f.Rules.RulePacks
		}
	}

	if f.Output != nil {
		if f.Output.Format != nil && *f.Output.Format != "" {
			cfg.Output.Format = *f.Output.Format
		}
	}

	return cfg
}
