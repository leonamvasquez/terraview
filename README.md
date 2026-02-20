# terraview

A standalone CLI tool that performs **semantic analysis of Terraform plans** using deterministic hard rules and optional AI review via multiple providers (Ollama, Gemini, Claude, DeepSeek).

**100% local by default. Multi-provider AI. Single binary.**

## Install

```bash
# One-line install
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

# Install LLM runtime (Ollama)
terraview install llm

# Or build from source
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

After installation:

```bash
terraview version
terraview --help
```

## Usage

```bash
# Navigate to any Terraform project
cd my-terraform-project

# Review the plan (auto-runs terraform init + plan if needed)
terraview review

# Review with an existing plan.json
terraview review --plan plan.json

# Review without AI (hard rules only)
terraview review --skip-llm

# Use a specific AI provider
terraview review --provider gemini
terraview review --provider claude
terraview review --provider deepseek

# Safe mode (light model, fewer resources)
terraview review --safe

# Output formats
terraview review --format compact          # minimal one-line output
terraview review --format json             # only write review.json

# Review, then apply if safe
terraview apply

# Run deterministic checks (no AI)
terraview test

# Detect infrastructure drift
terraview drift
```

## Philosophy: Infrastructure as Software

Infrastructure code deserves the same rigor as application code. This tool treats Terraform plans as first-class artifacts that should be reviewed with:

- **Deterministic rules** for known anti-patterns (open security groups, missing encryption, overly permissive IAM)
- **Semantic analysis** via AI for nuanced architectural and operational concerns
- **Versioned prompts** checked into source control alongside your infrastructure code
- **Structured output** that integrates into existing development workflows

## Commands

### Core Commands

#### `terraview review`

Analyzes a Terraform plan using deterministic rules and optional AI review.

If `--plan` is not specified, terraview automatically:
1. Detects `.tf` files in the current directory
2. Runs `terraform init` (if needed)
3. Runs `terraform plan -out=tfplan`
4. Exports `terraform show -json tfplan > plan.json`
5. Runs the review pipeline

```bash
terraview review                          # auto-detect and plan
terraview review --plan plan.json         # use existing plan
terraview review --skip-llm               # hard rules only
terraview review --provider gemini        # use Gemini AI
terraview review --model mistral:7b       # different model
terraview review --format compact         # minimal output
terraview review --strict                 # HIGH returns exit code 2
terraview review --safe                   # safe mode
```

#### `terraview apply`

Runs a full review, then conditionally applies the plan.

- **Blocks** if any CRITICAL findings are detected
- Shows review summary and asks for confirmation
- Use `--non-interactive` for CI pipelines

```bash
terraview apply                           # interactive
terraview apply --non-interactive         # CI mode
```

#### `terraview test`

Runs a deterministic test suite (no AI dependency):

1. `terraform fmt -check` — formatting verification
2. `terraform validate` — syntax and configuration checks
3. `terraform test` — native tests (Terraform 1.6+, if available)
4. Hard rules — deterministic rule evaluation

Exit codes: 0 = all passed, 1 = execution error, 2 = rule violations

```bash
terraview test
terraview test --rules custom-rules.yaml
```

#### `terraview drift`

Detect and classify infrastructure drift.

```bash
terraview drift
terraview drift --plan plan.json
terraview drift --format compact
```

### AI Management

#### `terraview ai`

Manage AI providers.

```bash
terraview ai list                         # list all providers and status
terraview ai current                      # show active provider
terraview ai test                         # validate provider connectivity
```

#### `terraview install llm`

Install the Ollama LLM runtime.

```bash
terraview install llm                     # install Ollama + pull default model
```

#### `terraview uninstall llm`

Remove the Ollama LLM runtime.

```bash
terraview uninstall llm                   # remove Ollama + data
```

### Utilities

```bash
terraview version                         # show version info
terraview update                          # self-update from GitHub
```

## CLI Flags

### Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--verbose, -v` | `false` | Enable verbose output |
| `--dir, -d` | `.` | Terraform workspace directory |

### Review Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--plan, -p` | (auto) | Path to plan JSON (auto-generates if omitted) |
| `--rules, -r` | (bundled) | Path to rules YAML file |
| `--prompts` | (bundled) | Path to prompts directory |
| `--output, -o` | `.` | Output directory for review files |
| `--provider` | (config) | AI provider (ollama, gemini, claude, deepseek) |
| `--model` | (config) | AI model to use |
| `--ollama-url` | (config) | Ollama server URL (legacy) |
| `--timeout` | (config) | AI request timeout in seconds |
| `--temperature` | (config) | AI temperature (0.0-1.0) |
| `--skip-llm` | `false` | Skip AI analysis |
| `--format` | `pretty` | Output format: pretty, compact, json |
| `--strict` | `false` | HIGH findings also return exit code 2 |
| `--safe` | `false` | Safe mode: light model, reduced resources |

### Apply Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--non-interactive` | `false` | Skip confirmation prompt (for CI) |
| All review flags | | Same as review command |

## Configuration (.terraview.yaml)

```yaml
llm:
  enabled: true
  provider: ollama                    # ollama, gemini, claude, deepseek
  model: llama3.1:8b
  url: http://localhost:11434
  api_key: ""                         # for cloud providers
  timeout_seconds: 120
  temperature: 0.2
  ollama:
    max_threads: 0                    # 0 = use all CPUs
    max_memory_mb: 0                  # 0 = no limit
    min_free_memory_mb: 1024

scoring:
  severity_weights:
    critical: 5
    high: 3
    medium: 1
    low: 0.5

rules:
  required_tags:
    - environment
    - owner
  rule_packs:
    - default
    - enterprise-security

output:
  format: pretty                      # pretty, compact, json
```

## Hard Rules

Rules are defined in YAML and support these condition operators:

- `equals` / `not_equals` — exact string match
- `contains` / `not_contains` — substring search
- `exists` / `not_exists` — field presence check
- `is_true` / `is_false` — boolean check
- `is_action` — match resource action (create, delete, update, replace)
- `contains_in_list` — check if list contains value

### Default Rules

| ID | Name | Severity |
|----|------|----------|
| SEC001 | SSH Open to Internet | HIGH |
| SEC002 | S3 Bucket Without Encryption | HIGH |
| SEC003 | IAM Policy with Wildcard Actions | CRITICAL |
| SEC004 | IAM Policy with Wildcard Resources | HIGH |
| SEC005 | RDS Publicly Accessible | HIGH |
| SEC006 | S3 Bucket Public ACL | HIGH |
| SEC007 | Security Group Allows All Traffic | CRITICAL |
| REL001 | RDS Without Multi-AZ | MEDIUM |
| REL002 | RDS Without Backup | HIGH |
| BP001 | S3 Bucket Without Versioning | MEDIUM |
| BP002 | EBS Volume Without Encryption | MEDIUM |
| COMP001 | CloudWatch Logs Without Retention | LOW |
| TAG001 | Missing Required Tags | MEDIUM |
| DEL001 | Critical Resource Deletion | HIGH |

### Custom Rules

```yaml
version: "1.0"
required_tags:
  - Environment
  - CostCenter
rules:
  - id: CUSTOM001
    name: My Custom Rule
    description: "Description of what this checks"
    severity: HIGH
    category: security
    remediation: "How to fix it"
    enabled: true
    targets:
      - aws_s3_bucket
    conditions:
      - field: some_field
        operator: equals
        value: "bad_value"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues or MEDIUM/LOW/INFO only |
| 1 | HIGH severity findings |
| 2 | CRITICAL severity findings (blocks apply) |

## CI Integration

### GitHub Actions

```yaml
name: Terraform Review
on:
  pull_request:
    paths: ['**.tf']

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Install terraview
        run: curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

      - name: Review
        run: terraview review --skip-llm

      - name: Post PR Comment
        if: always()
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: review.md
```

### GitLab CI

```yaml
terraform-review:
  stage: validate
  script:
    - curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
    - terraview review --skip-llm
  artifacts:
    paths: [review.json, review.md]
    when: always
```

## Scoring

Scores are calculated on a 0-10 scale using weighted penalties:

**Severity weights:** CRITICAL=5.0, HIGH=3.0, MEDIUM=1.0, LOW=0.5, INFO=0.0

**Category weights:** Security=2.0, Compliance=1.5, Reliability=1.5, Best Practice=1.0, Maintainability=1.0

## Development

```bash
make build       # Build for current platform
make test        # Run tests with race detection
make dist        # Build for all platforms
make install     # Install locally
make help        # Show all targets
```

## Roadmap

- [ ] Azure and GCP rule sets
- [ ] Custom scoring profiles
- [ ] SARIF output format
- [ ] Terraform module-aware analysis
- [ ] Plugin system for custom rules
- [ ] Historical trend tracking
- [ ] Integration with OPA/Rego policies

## License

MIT
