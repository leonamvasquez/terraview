package parser

// TerraformPlan represents the top-level structure of terraform show -json output.
type TerraformPlan struct {
	FormatVersion    string              `json:"format_version"`
	TerraformVersion string              `json:"terraform_version"`
	PlannedValues    PlannedValues       `json:"planned_values"`
	ResourceChanges  []ResourceChange    `json:"resource_changes"`
	Configuration    Configuration       `json:"configuration"`
	Variables        map[string]Variable `json:"variables,omitempty"`
}

type PlannedValues struct {
	RootModule Module `json:"root_module"`
}

type Module struct {
	Resources    []PlannedResource `json:"resources,omitempty"`
	ChildModules []Module          `json:"child_modules,omitempty"`
	Address      string            `json:"address,omitempty"`
}

type PlannedResource struct {
	Address       string                 `json:"address"`
	Mode          string                 `json:"mode"`
	Type          string                 `json:"type"`
	Name          string                 `json:"name"`
	ProviderName  string                 `json:"provider_name"`
	SchemaVersion int                    `json:"schema_version"`
	Values        map[string]interface{} `json:"values"`
}

type ResourceChange struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address,omitempty"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	ProviderName  string `json:"provider_name"`
	Change        Change `json:"change"`
}

type Change struct {
	Actions      []string               `json:"actions"`
	Before       map[string]interface{} `json:"before"`
	After        map[string]interface{} `json:"after"`
	AfterUnknown map[string]interface{} `json:"after_unknown,omitempty"`
}

type Configuration struct {
	ProviderConfig map[string]ProviderConfig `json:"provider_config,omitempty"`
	RootModule     ConfigModule              `json:"root_module"`
}

type ProviderConfig struct {
	Name        string                 `json:"name"`
	Expressions map[string]interface{} `json:"expressions,omitempty"`
}

type ConfigModule struct {
	Resources   []ConfigResource      `json:"resources,omitempty"`
	Variables   map[string]Variable   `json:"variables,omitempty"`
	ModuleCalls map[string]ModuleCall `json:"module_calls,omitempty"`
}

type ModuleCall struct {
	Source            string                 `json:"source,omitempty"`
	VersionConstraint string                 `json:"version_constraint,omitempty"`
	Expressions       map[string]interface{} `json:"expressions,omitempty"`
	Module            *ConfigModule          `json:"module,omitempty"`
}

type ConfigResource struct {
	Address           string                 `json:"address"`
	Mode              string                 `json:"mode"`
	Type              string                 `json:"type"`
	Name              string                 `json:"name"`
	ProviderConfigKey string                 `json:"provider_config_key"`
	Expressions       map[string]interface{} `json:"expressions,omitempty"`
}

type Variable struct {
	Default     interface{} `json:"default,omitempty"`
	Description string      `json:"description,omitempty"`
}

// NormalizedResource is a simplified representation of a resource change for rule evaluation.
type NormalizedResource struct {
	Address      string                 `json:"address"`
	Type         string                 `json:"type"`
	Name         string                 `json:"name"`
	Action       string                 `json:"action"`
	Provider     string                 `json:"provider"`
	Values       map[string]interface{} `json:"values"`
	BeforeValues map[string]interface{} `json:"before_values,omitempty"`
}
