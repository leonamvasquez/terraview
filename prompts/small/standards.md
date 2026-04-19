Check IaC hygiene patterns that require plan-wide reasoning.

### Key checks

1. **Tagging**: Resources missing mandatory tags (Environment, Owner, Project, CostCenter); inconsistent tag values across related resources
2. **Naming**: Inconsistent naming conventions across resource types in the same environment
3. **Versioning**: Provider or module versions unpinned (floating `~>` or no constraint)
4. **Hygiene**: Hardcoded values that should be variables; deprecated resource types or arguments

### Severity

- **HIGH**: Missing tags on all resources (cost/ownership unattributable)
- **MEDIUM**: Inconsistent conventions across the plan
- **LOW**: Individual hygiene issues
