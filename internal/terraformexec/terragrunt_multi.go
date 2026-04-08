package terraformexec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/parser"
)

// TerragruntMultiExecutor handles multi-module Terragrunt projects.
// It discovers child modules, plans each one sequentially, and merges
// the results into a single plan.json for the downstream pipeline.
type TerragruntMultiExecutor struct {
	rootDir    string
	configFile string
	modules    []string // absolute paths to module directories
}

// NewTerragruntMultiExecutor creates a multi-module executor for a Terragrunt root directory.
func NewTerragruntMultiExecutor(rootDir string, configFile string) (*TerragruntMultiExecutor, error) {
	absDir, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve root directory: %w", err)
	}

	// Verify terragrunt binary exists
	if _, err := resolveTerragruntBinary(); err != nil {
		return nil, err
	}

	modules, err := DiscoverTerragruntModules(absDir)
	if err != nil {
		return nil, err
	}

	return &TerragruntMultiExecutor{
		rootDir:    absDir,
		configFile: configFile,
		modules:    modules,
	}, nil
}

// WorkDir returns the root directory.
func (e *TerragruntMultiExecutor) WorkDir() string {
	return e.rootDir
}

// NeedsInit returns false — init is handled per-module inside Plan().
func (e *TerragruntMultiExecutor) NeedsInit() bool {
	return false
}

// Init is a no-op — each module is initialized individually inside Plan().
func (e *TerragruntMultiExecutor) Init() error {
	return nil
}

// Plan generates plans for all discovered modules, merges them into a single
// plan.json, and returns its path. Modules that fail are skipped with a warning;
// the scan proceeds with partial results.
func (e *TerragruntMultiExecutor) Plan() (string, error) {
	unlock, err := acquireLock(e.rootDir)
	if err != nil {
		return "", err
	}
	defer unlock()

	total := len(e.modules)
	plans := make(map[string]*parser.TerraformPlan)
	var warnings []string

	fmt.Fprintf(os.Stderr, "%s Discovered %d Terragrunt modules\n", output.Prefix(), total)

	for i, modDir := range e.modules {
		modName := filepath.Base(modDir)

		fmt.Fprintf(os.Stderr, "%s Planning module %s (%d/%d)...\n",
			output.Prefix(), modName, i+1, total)

		modExec, err := NewTerragruntExecutor(modDir, e.configFile)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", modName, err))
			continue
		}

		if modExec.NeedsInit() {
			if err := modExec.Init(); err != nil {
				warnings = append(warnings, fmt.Sprintf("%s (init): %v", modName, err))
				continue
			}
		}

		planPath, err := modExec.Plan()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s (plan): %v", modName, err))
			continue
		}

		p := parser.NewParser()
		plan, err := p.ParseFile(planPath)
		if err != nil {
			// Module with no resource changes is normal — skip silently
			if strings.Contains(err.Error(), "no resource changes") {
				fmt.Fprintf(os.Stderr, "%s Module %s has no changes, skipping\n",
					output.Prefix(), modName)
				continue
			}
			warnings = append(warnings, fmt.Sprintf("%s (parse): %v", modName, err))
			continue
		}

		plans[modName] = plan
	}

	if len(plans) == 0 {
		if len(warnings) > 0 {
			return "", fmt.Errorf("all modules failed:\n  %s", strings.Join(warnings, "\n  "))
		}
		return "", fmt.Errorf("no modules produced resource changes")
	}

	if len(warnings) > 0 {
		fmt.Fprintf(os.Stderr, "%s Warning: %d module(s) had issues:\n", output.Prefix(), len(warnings))
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "  - %s\n", w)
		}
	}

	fmt.Fprintf(os.Stderr, "%s Merging %d module plans...\n", output.Prefix(), len(plans))

	merged, err := parser.MergeTerraformPlans(plans)
	if err != nil {
		return "", fmt.Errorf("failed to merge plans: %w", err)
	}

	mergedJSON, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal merged plan: %w", err)
	}

	planPath := filepath.Join(e.rootDir, "plan.json")
	if err := os.WriteFile(planPath, mergedJSON, 0644); err != nil {
		return "", fmt.Errorf("failed to write merged plan.json: %w", err)
	}

	return planPath, nil
}

// Apply is not supported for multi-module roots.
func (e *TerragruntMultiExecutor) Apply() error {
	return fmt.Errorf("multi-module apply is not supported from root.\nUse 'terraview scan --terragrunt -d <module>' to apply individual modules")
}

// IsTerragruntRootWithModules returns true if dir contains a terragrunt.hcl
// and at least one child directory also contains a terragrunt.hcl.
func IsTerragruntRootWithModules(dir string) bool {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}

	// Root must have terragrunt.hcl
	rootHCL := filepath.Join(absDir, "terragrunt.hcl")
	if _, err := os.Stat(rootHCL); err != nil {
		return false
	}

	// Check for at least one child module
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		childHCL := filepath.Join(absDir, entry.Name(), "terragrunt.hcl")
		if _, err := os.Stat(childHCL); err == nil {
			return true
		}
	}

	return false
}

// DiscoverTerragruntModules finds all immediate child directories that contain
// a terragrunt.hcl file. Returns sorted absolute paths. Hidden directories
// (prefixed with '.') are skipped.
func DiscoverTerragruntModules(rootDir string) ([]string, error) {
	absDir, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve root directory: %w", err)
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var modules []string
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		childHCL := filepath.Join(absDir, entry.Name(), "terragrunt.hcl")
		if _, err := os.Stat(childHCL); err == nil {
			modules = append(modules, filepath.Join(absDir, entry.Name()))
		}
	}

	if len(modules) == 0 {
		return nil, fmt.Errorf("no Terragrunt modules found in %s", absDir)
	}

	sort.Strings(modules)
	return modules, nil
}
