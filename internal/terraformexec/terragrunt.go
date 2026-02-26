package terraformexec

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/leonamvasquez/terraview/internal/output"
)

// TerragruntExecutor abstracts terragrunt CLI operations.
// It implements PlanExecutor using the terragrunt binary, which wraps terraform
// but handles multi-module dependencies, remote state, and code generation.
type TerragruntExecutor struct {
	workDir    string
	binaryPath string
	configFile string // --terragrunt-config: path to custom terragrunt.hcl
}

// NewTerragruntExecutor creates a new TerragruntExecutor for the given working directory.
// configFile is optional — when non-empty, it's passed as --terragrunt-config to all commands.
func NewTerragruntExecutor(workDir string, configFile string) (*TerragruntExecutor, error) {
	absDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve workspace path: %w", err)
	}

	info, err := os.Stat(absDir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("workspace directory does not exist: %s", absDir)
	}

	binaryPath, err := resolveTerragruntBinary()
	if err != nil {
		return nil, err
	}

	// Resolve config file to absolute path if provided
	var absConfig string
	if configFile != "" {
		absConfig, err = filepath.Abs(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve config file path: %w", err)
		}
		if _, err := os.Stat(absConfig); err != nil {
			return nil, fmt.Errorf("terragrunt config file not found: %s", absConfig)
		}
	}

	return &TerragruntExecutor{
		workDir:    absDir,
		binaryPath: binaryPath,
		configFile: absConfig,
	}, nil
}

// WorkDir returns the resolved working directory.
func (e *TerragruntExecutor) WorkDir() string {
	return e.workDir
}

// NeedsInit checks whether terragrunt init needs to be run.
// Terragrunt uses .terragrunt-cache/ instead of .terraform/.
func (e *TerragruntExecutor) NeedsInit() bool {
	cacheDir := filepath.Join(e.workDir, ".terragrunt-cache")
	_, err := os.Stat(cacheDir)
	return err != nil
}

// Init runs terragrunt init.
func (e *TerragruntExecutor) Init() error {
	_, err := output.SpinWhile("Running terragrunt init...", func() (string, error) {
		stderr, runErr := e.runSilent("init", "-input=false")
		if runErr != nil {
			return "", fmt.Errorf("%w\n%s", runErr, stderr)
		}
		return "", nil
	})
	if err != nil {
		return fmt.Errorf("terragrunt init failed: %w", err)
	}
	return nil
}

// Plan runs terragrunt plan and exports the plan to JSON.
// Returns the path to the generated plan.json file.
func (e *TerragruntExecutor) Plan() (string, error) {
	unlock, err := acquireLock(e.workDir)
	if err != nil {
		return "", err
	}
	defer unlock()

	// Use absolute paths so terragrunt places files in our workDir,
	// not inside .terragrunt-cache/<hash>/
	planBinary := filepath.Join(e.workDir, "tfplan")
	planJSON := filepath.Join(e.workDir, "plan.json")

	planSpinner := output.NewSpinner("Running terragrunt plan...")
	planSpinner.Start()
	stderr, err := e.runSilent("plan", fmt.Sprintf("-out=%s", planBinary), "-input=false", "-detailed-exitcode")
	// Exit code 2 from terragrunt plan means changes detected — that's expected
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 2 {
				// Changes present — this is normal
			} else {
				planSpinner.Stop(false)
				if stderr != "" {
					fmt.Fprintf(os.Stderr, "%s\n", stderr)
				}
				return "", fmt.Errorf("terragrunt plan failed: %w", err)
			}
		} else {
			planSpinner.Stop(false)
			if stderr != "" {
				fmt.Fprintf(os.Stderr, "%s\n", stderr)
			}
			return "", fmt.Errorf("terragrunt plan failed: %w", err)
		}
	}

	if _, err := os.Stat(planBinary); err != nil {
		planSpinner.Stop(false)
		return "", fmt.Errorf("terragrunt plan did not produce tfplan file: %w", err)
	}
	planSpinner.Stop(true)

	out, err := output.SpinWhile("Exporting plan to JSON...", func() (string, error) {
		return e.run("show", "-json", planBinary)
	})
	if err != nil {
		return "", fmt.Errorf("terragrunt show -json failed: %w", err)
	}

	if err := os.WriteFile(planJSON, []byte(out), 0644); err != nil {
		return "", fmt.Errorf("failed to write plan.json: %w", err)
	}

	return planJSON, nil
}

// Apply runs terragrunt apply with the binary plan file.
func (e *TerragruntExecutor) Apply() error {
	planBinary := filepath.Join(e.workDir, "tfplan")
	if _, err := os.Stat(planBinary); err != nil {
		return fmt.Errorf("no tfplan file found — run 'terraview scan --terragrunt' first")
	}

	fmt.Fprintf(os.Stderr, "%s Running terragrunt apply...\n", output.Prefix())
	_, err := e.runPassthrough("apply", planBinary)
	if err != nil {
		return fmt.Errorf("terragrunt apply failed: %w", err)
	}
	return nil
}

// injectConfig inserts --terragrunt-config after the subcommand (first arg).
// Terragrunt v0.44.x expects: terragrunt plan --terragrunt-config dev.hcl [flags...]
func (e *TerragruntExecutor) injectConfig(args []string) []string {
	if e.configFile == "" || len(args) == 0 {
		return args
	}
	result := make([]string, 0, len(args)+2)
	result = append(result, args[0])
	result = append(result, "--terragrunt-config", e.configFile)
	result = append(result, args[1:]...)
	return result
}

// run executes a terragrunt command and captures stdout.
func (e *TerragruntExecutor) run(args ...string) (string, error) {
	cmd := exec.Command(e.binaryPath, e.injectConfig(args)...)
	cmd.Dir = e.workDir

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// runPassthrough executes terragrunt with stdout/stderr connected to the terminal.
func (e *TerragruntExecutor) runPassthrough(args ...string) (string, error) {
	cmd := exec.Command(e.binaryPath, e.injectConfig(args)...)
	cmd.Dir = e.workDir

	var combined bytes.Buffer

	cmd.Stdout = os.Stdout
	cmd.Stderr = &combined

	err := cmd.Run()
	return combined.String(), err
}

// runSilent executes terragrunt capturing all output without displaying it.
func (e *TerragruntExecutor) runSilent(args ...string) (string, error) {
	cmd := exec.Command(e.binaryPath, e.injectConfig(args)...)
	cmd.Dir = e.workDir

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Terragrunt is verbose by default; suppress with env var
	cmd.Env = append(os.Environ(), "TERRAGRUNT_LOG_LEVEL=error")

	err := cmd.Run()
	return stderr.String(), err
}

// resolveTerragruntBinary finds the terragrunt binary.
func resolveTerragruntBinary() (string, error) {
	// Check for terragrunt in PATH
	path, err := exec.LookPath("terragrunt")
	if err != nil {
		return "", fmt.Errorf("terragrunt not found in PATH.\n\nInstall it from https://terragrunt.gruntwork.io/docs/getting-started/install/\n\nOr use Homebrew:\n  brew install terragrunt")
	}

	// Verify it's executable
	info, statErr := os.Stat(path)
	if statErr != nil {
		return "", fmt.Errorf("terragrunt binary not accessible: %w", statErr)
	}
	// On Windows, executability is determined by file extension (.exe, .bat, etc.),
	// not by permission bits. os.Stat().Mode() never sets execute bits on Windows,
	// so this check would always fail there.
	if runtime.GOOS != "windows" {
		if info.Mode()&0111 == 0 {
			return "", fmt.Errorf("terragrunt binary is not executable: %s", path)
		}
	}

	return path, nil
}

// IsTerragruntProject checks if a directory contains Terragrunt configuration.
func IsTerragruntProject(dir string) bool {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}

	indicators := []string{
		filepath.Join(absDir, "terragrunt.hcl"),
		filepath.Join(absDir, ".terragrunt-cache"),
	}
	for _, p := range indicators {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}

	// Check parent directories for root terragrunt.hcl (common pattern)
	current := absDir
	for i := 0; i < 5; i++ { // max 5 levels up
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		rootHCL := filepath.Join(parent, "terragrunt.hcl")
		if _, err := os.Stat(rootHCL); err == nil {
			// Found a parent terragrunt.hcl — check if current dir also has one
			childHCL := filepath.Join(absDir, "terragrunt.hcl")
			if _, err := os.Stat(childHCL); err == nil {
				return true
			}
		}
		current = parent
	}

	return false
}

// ValidateTerragruntWorkspace validates that a directory is a valid Terragrunt workspace.
func ValidateTerragruntWorkspace(dir string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to resolve directory: %w", err)
	}

	info, err := os.Stat(absDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("not a valid directory: %s", absDir)
	}

	hclPath := filepath.Join(absDir, "terragrunt.hcl")
	if _, err := os.Stat(hclPath); err != nil {
		return fmt.Errorf("no terragrunt.hcl found in %s", absDir)
	}

	// Check for *.tf files (Terragrunt modules need them or generate them)
	tfMatches, _ := filepath.Glob(filepath.Join(absDir, "*.tf"))
	hclMatches, _ := filepath.Glob(filepath.Join(absDir, "*.hcl"))
	if len(tfMatches) == 0 && len(hclMatches) <= 1 {
		// Only terragrunt.hcl and no .tf files — might be root config only
		// This is valid for Terragrunt projects that generate tf from terragrunt
		entries, err := os.ReadDir(absDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
					childHCL := filepath.Join(absDir, entry.Name(), "terragrunt.hcl")
					if _, err := os.Stat(childHCL); err == nil {
						return fmt.Errorf("this appears to be a Terragrunt root directory with child modules.\nRun terraview from a specific module:\n  terraview scan checkov --terragrunt -d %s", entry.Name())
					}
				}
			}
		}
	}

	return nil
}
