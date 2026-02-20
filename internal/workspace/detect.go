package workspace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DetectResult holds information about a detected Terraform workspace.
type DetectResult struct {
	Dir              string
	HasTFFiles       bool
	HasLockFile      bool
	IsInitialized    bool
	HasPlanJSON      bool
	PlanJSONPath     string
	HasModules       bool
	TFFileCount      int
	TerraformVersion string
}

// Detect examines a directory to determine if it's a Terraform workspace.
func Detect(dir string) (*DetectResult, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve directory: %w", err)
	}

	info, err := os.Stat(absDir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("not a valid directory: %s", absDir)
	}

	result := &DetectResult{Dir: absDir}

	// Check for .tf files
	tfMatches, _ := filepath.Glob(filepath.Join(absDir, "*.tf"))
	result.HasTFFiles = len(tfMatches) > 0
	result.TFFileCount = len(tfMatches)

	// Check for .terraform.lock.hcl (alternative indicator)
	lockFile := filepath.Join(absDir, ".terraform.lock.hcl")
	if _, err := os.Stat(lockFile); err == nil {
		result.HasLockFile = true
	}

	// Check for .terraform directory
	tfDir := filepath.Join(absDir, ".terraform")
	if fi, err := os.Stat(tfDir); err == nil && fi.IsDir() {
		result.IsInitialized = true
	}

	// Check for modules directory
	modulesDir := filepath.Join(absDir, ".terraform", "modules")
	if fi, err := os.Stat(modulesDir); err == nil && fi.IsDir() {
		result.HasModules = true
	}

	// Check for existing plan.json
	planPath := filepath.Join(absDir, "plan.json")
	if _, err := os.Stat(planPath); err == nil {
		result.HasPlanJSON = true
		result.PlanJSONPath = planPath
	}

	// Try to get terraform version
	result.TerraformVersion = detectTerraformVersion()

	return result, nil
}

// Validate returns an error if the directory is not a valid Terraform workspace.
func Validate(dir string) error {
	result, err := Detect(dir)
	if err != nil {
		return err
	}

	// Check terraform is installed first
	if result.TerraformVersion == "" {
		if _, lookErr := exec.LookPath("terraform"); lookErr != nil {
			return fmt.Errorf(
				"terraform is not installed or not in PATH\n\n" +
					"Install Terraform:\n" +
					"  macOS:  brew install terraform\n" +
					"  Linux:  https://developer.hashicorp.com/terraform/install\n",
			)
		}
	}

	// Accept .tf files OR .terraform.lock.hcl as workspace indicators
	if !result.HasTFFiles && !result.HasLockFile {
		return fmt.Errorf(
			"no Terraform files found in %s\n\n"+
				"Expected: *.tf files or .terraform.lock.hcl\n\n"+
				"terraview must be run from a directory containing Terraform configuration.\n"+
				"Navigate to your Terraform project directory and try again:\n\n"+
				"  cd /path/to/terraform/project\n"+
				"  terraview review\n",
			result.Dir,
		)
	}

	return nil
}

// detectTerraformVersion tries to get the terraform version string.
func detectTerraformVersion() string {
	path, err := exec.LookPath("terraform")
	if err != nil {
		return ""
	}

	cmd := exec.Command(path, "version", "-json")
	out, err := cmd.Output()
	if err != nil {
		// Try without -json
		cmd = exec.Command(path, "version")
		out, err = cmd.Output()
		if err != nil {
			return ""
		}
	}

	version := strings.TrimSpace(string(out))
	// Extract first line only
	if idx := strings.IndexByte(version, '\n'); idx != -1 {
		version = version[:idx]
	}
	return version
}
