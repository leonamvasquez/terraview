Evaluate architecture patterns that require reasoning about the overall design — not single-resource checks.

### Key checks

1. **HA asymmetry**: Multi-AZ compute backed by single-AZ database; `desired_count = 1` on production services
2. **Blast radius**: Shared VPC/IAM/security-group changes propagating to many dependents; missing `prevent_destroy` on stateful resources
3. **Scaling mismatch**: Auto-scaling compute → fixed-capacity database (connection exhaustion risk)
4. **Network**: Resources in default VPC; missing private subnets for backend services; public subnets without NAT for outbound
5. **Data lifecycle**: Stateful resources without backup/snapshot policies; unbounded storage growth

### Severity

- **CRITICAL**: Single point of failure for stateful production resources, cascade deletion risk
- **HIGH**: Missing HA for databases, no auto-scaling on production compute
- **MEDIUM**: Over-provisioned resources, missing observability
- **LOW**: Minor topology improvements
