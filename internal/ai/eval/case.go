package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Case describes one evaluation case: the path to a Terraform plan JSON
// file plus the Golden spec the provider must satisfy.
type Case struct {
	Name     string
	PlanPath string
	Golden   Golden
}

// Golden codifies the expected shape of an AI response for a given plan.
// Fields are all optional — an empty Golden imposes no assertions, which is
// occasionally useful for smoke-testing that the provider returns *any*
// result without crashing.
type Golden struct {
	// Description is a free-form note explaining what this case exercises.
	Description string `yaml:"description"`

	// RequiredTopics are substrings that must appear in at least one finding
	// (Message or RuleID), case-insensitive. Use to assert that specific risk
	// categories surface — e.g. "encryption", "public access", "iam".
	RequiredTopics []string `yaml:"required_topics"`

	// RequiredResources are resource addresses that must be referenced by at
	// least one finding. Use to assert that the model noticed a particular
	// resource in the plan.
	RequiredResources []string `yaml:"required_resources"`

	// MinSeverity sets a floor on the finding count per severity level.
	// Keys are severity strings (CRITICAL/HIGH/MEDIUM/LOW/INFO); values are
	// the minimum number of findings required at that level.
	MinSeverity map[string]int `yaml:"min_severity"`

	// MaxFindings caps the total number of findings. Useful when prompts
	// start emitting noise and the budget matters. 0 = no cap.
	MaxFindings int `yaml:"max_findings"`

	// SummaryContains are substrings required in the summary text,
	// case-insensitive. Empty list = no assertion.
	SummaryContains []string `yaml:"summary_contains"`
}

// LoadCase reads a single case directory containing `plan.json` and
// `golden.yaml`. Returns an error if either file is missing or malformed.
func LoadCase(dir string) (Case, error) {
	name := filepath.Base(dir)
	planPath := filepath.Join(dir, "plan.json")
	goldenPath := filepath.Join(dir, "golden.yaml")

	if _, err := os.Stat(planPath); err != nil {
		return Case{}, fmt.Errorf("load case %q: plan.json: %w", name, err)
	}

	data, err := os.ReadFile(goldenPath)
	if err != nil {
		return Case{}, fmt.Errorf("load case %q: golden.yaml: %w", name, err)
	}

	var g Golden
	if err := yaml.Unmarshal(data, &g); err != nil {
		return Case{}, fmt.Errorf("load case %q: parse golden.yaml: %w", name, err)
	}

	return Case{Name: name, PlanPath: planPath, Golden: g}, nil
}

// LoadCases walks root and returns every subdirectory that contains both a
// plan.json and a golden.yaml. Subdirectories are sorted alphabetically so
// runs are deterministic.
func LoadCases(root string) ([]Case, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read eval root %s: %w", root, err)
	}

	var cases []Case
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "golden.yaml")); err != nil {
			continue
		}
		c, err := LoadCase(dir)
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}

	sort.Slice(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })
	return cases, nil
}
