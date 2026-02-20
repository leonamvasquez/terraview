package terraformexec

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Executor abstracts terraform CLI operations.
type Executor struct {
	workDir    string
	binaryPath string
}

// NewExecutor creates a new Executor for the given working directory.
// It resolves the terraform binary path and validates it exists.
func NewExecutor(workDir string) (*Executor, error) {
	absDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve workspace path: %w", err)
	}

	info, err := os.Stat(absDir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("workspace directory does not exist: %s", absDir)
	}

	binaryPath, err := resolveTerraformBinary()
	if err != nil {
		return nil, err
	}

	return &Executor{
		workDir:    absDir,
		binaryPath: binaryPath,
	}, nil
}

// WorkDir returns the resolved working directory.
func (e *Executor) WorkDir() string {
	return e.workDir
}

// Version returns the installed terraform version string.
func (e *Executor) Version() (string, error) {
	out, err := e.run("version", "-json")
	if err != nil {
		// Fallback without -json for older versions
		out, err = e.run("version")
		if err != nil {
			return "", fmt.Errorf("failed to get terraform version: %w", err)
		}
	}
	return strings.TrimSpace(out), nil
}

// Init runs terraform init if the .terraform directory does not exist.
func (e *Executor) Init() error {
	tfDir := filepath.Join(e.workDir, ".terraform")
	if _, err := os.Stat(tfDir); err == nil {
		return nil // already initialized
	}

	fmt.Println("[terraview] Running terraform init...")
	_, err := e.runPassthrough("init", "-input=false")
	if err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}
	return nil
}

// NeedsInit checks whether terraform init needs to be run.
func (e *Executor) NeedsInit() bool {
	tfDir := filepath.Join(e.workDir, ".terraform")
	_, err := os.Stat(tfDir)
	return err != nil
}

// Plan runs terraform plan and outputs a binary plan file, then converts to JSON.
// Returns the path to the generated plan.json file.
func (e *Executor) Plan() (string, error) {
	planBinary := filepath.Join(e.workDir, "tfplan")
	planJSON := filepath.Join(e.workDir, "plan.json")

	fmt.Println("[terraview] Running terraform plan...")
	_, err := e.runPassthrough("plan", "-out=tfplan", "-input=false", "-detailed-exitcode")
	// Exit code 2 from terraform plan means changes detected — that's expected
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 2 {
				// Changes present — this is normal
			} else {
				return "", fmt.Errorf("terraform plan failed: %w", err)
			}
		} else {
			return "", fmt.Errorf("terraform plan failed: %w", err)
		}
	}

	if _, err := os.Stat(planBinary); err != nil {
		return "", fmt.Errorf("terraform plan did not produce tfplan file: %w", err)
	}

	fmt.Println("[terraview] Exporting plan to JSON...")
	out, err := e.run("show", "-json", "tfplan")
	if err != nil {
		return "", fmt.Errorf("terraform show -json failed: %w", err)
	}

	if err := os.WriteFile(planJSON, []byte(out), 0644); err != nil {
		return "", fmt.Errorf("failed to write plan.json: %w", err)
	}

	return planJSON, nil
}

// FmtCheck runs terraform fmt -check and returns whether files are formatted.
func (e *Executor) FmtCheck() (string, error) {
	fmt.Println("[terraview] Running terraform fmt -check...")
	out, err := e.run("fmt", "-check", "-recursive")
	if err != nil {
		return out, fmt.Errorf("terraform fmt check failed (unformatted files detected): %w", err)
	}
	return out, nil
}

// Validate runs terraform validate and returns the output.
func (e *Executor) Validate() (string, error) {
	fmt.Println("[terraview] Running terraform validate...")
	out, err := e.runPassthrough("validate")
	if err != nil {
		return out, fmt.Errorf("terraform validate failed: %w", err)
	}
	return out, nil
}

// Test runs terraform test (available in Terraform 1.6+).
// Returns output and a boolean indicating if the command is available.
func (e *Executor) Test() (string, bool, error) {
	fmt.Println("[terraview] Running terraform test...")
	out, err := e.runPassthrough("test")
	if err != nil {
		// Check if it's an "unknown command" error
		if strings.Contains(out, "unknown command") || strings.Contains(out, "Unknown command") {
			return "", false, nil
		}
		return out, true, fmt.Errorf("terraform test failed: %w", err)
	}
	return out, true, nil
}

// Apply runs terraform apply with the binary plan file.
func (e *Executor) Apply() error {
	planBinary := filepath.Join(e.workDir, "tfplan")
	if _, err := os.Stat(planBinary); err != nil {
		return fmt.Errorf("no tfplan file found — run 'terraview review' first")
	}

	fmt.Println("[terraview] Running terraform apply...")
	_, err := e.runPassthrough("apply", "tfplan")
	if err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}
	return nil
}

// Cleanup removes temporary plan files.
func (e *Executor) Cleanup() {
	os.Remove(filepath.Join(e.workDir, "tfplan"))
}

// run executes a terraform command and captures stdout.
func (e *Executor) run(args ...string) (string, error) {
	cmd := exec.Command(e.binaryPath, args...)
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

// runPassthrough executes terraform with stdout/stderr connected to the terminal.
func (e *Executor) runPassthrough(args ...string) (string, error) {
	cmd := exec.Command(e.binaryPath, args...)
	cmd.Dir = e.workDir

	var combined bytes.Buffer

	cmd.Stdout = os.Stdout
	cmd.Stderr = &combined

	err := cmd.Run()
	return combined.String(), err
}

// resolveTerraformBinary finds the terraform binary.
func resolveTerraformBinary() (string, error) {
	path, err := exec.LookPath("terraform")
	if err != nil {
		return "", fmt.Errorf("terraform not found in PATH. Install it from https://developer.hashicorp.com/terraform/install")
	}
	return path, nil
}
