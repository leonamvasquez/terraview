Evaluate Terraform code quality and operational standards.
Focus on patterns that cause REAL operational problems — not cosmetic preferences.

### 1. Resource tagging
- Missing mandatory tags that break cost allocation, ownership, and incident response:
  - `Environment` (prod/staging/dev) — critical for blast radius assessment
  - `Team` or `Owner` — critical for incident routing
  - `Project` or `Application` — critical for cost allocation
  - `ManagedBy` (terraform) — prevents manual drift
- Inconsistent tag keys across resources (e.g., `env` vs `Environment` vs `environment`)
- Tags on parent resource but not on child resources (e.g., VPC tagged, subnets not)
- **AWS**: Missing `aws_default_tags` in provider block (tag inheritance)
- **Azure**: Missing `tags` on resource group (does not auto-propagate)
- **GCP**: Missing `labels` (GCP equivalent of tags)

### 2. Naming conventions
- Resources without descriptive names (default cloud-generated names)
- Inconsistent naming patterns across the same plan (e.g., `my-vpc` vs `main_vpc` vs `VPC1`)
- Names that don't encode environment/purpose (impossible to identify in console)
- Recommended pattern: `{project}-{environment}-{resource_type}-{identifier}`
- Only flag as finding if naming inconsistency could cause operational confusion

### 3. Terraform hygiene
- Missing `description` on variables and outputs (especially in shared modules)
- Variables without `type` constraints or `validation` blocks
- Hardcoded values that should be variables (AMI IDs, CIDRs, instance types)
- Missing `terraform { required_version }` constraint
- Provider versions unpinned or using `>=` without upper bound
- Deprecated resource types or attributes still in use
- Missing `lifecycle` blocks on stateful resources

### 4. Versioning and immutability
- S3/GCS buckets without versioning (data recovery risk)
- Lambda/Cloud Functions using `latest` runtime instead of pinned version
- Container images using `:latest` tag instead of digest or semantic version
- Module sources without version pinning (`?ref=` for git, version constraint for registry)

### 5. Documentation signals
- Complex modules (>10 resources) without README or variable descriptions
- Outputs that expose sensitive values without `sensitive = true`
- Missing `depends_on` where implicit dependency is fragile

### Severity calibration for standards
- **HIGH**: Missing tags that break cost allocation or incident response for production resources
- **MEDIUM**: Inconsistent naming causing operational confusion, unpinned versions
- **LOW**: Missing descriptions, minor naming deviations, cosmetic hygiene
- **INFO**: Positive patterns worth noting, documentation suggestions
