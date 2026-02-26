package terraformexec

// PlanExecutor is the interface for IaC plan generation backends.
// Both Terraform and Terragrunt implement this interface.
type PlanExecutor interface {
	// WorkDir returns the resolved working directory.
	WorkDir() string

	// NeedsInit checks whether the workspace requires initialization.
	NeedsInit() bool

	// Init initializes the workspace (terraform init / terragrunt init).
	Init() error

	// Plan generates a plan and exports it to JSON.
	// Returns the path to the generated plan.json file.
	Plan() (string, error)

	// Apply runs the plan (terraform apply / terragrunt apply).
	Apply() error
}
