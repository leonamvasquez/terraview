Evaluate infrastructure against common regulatory and compliance frameworks.
Only flag findings where the Terraform plan ACTIVELY creates a compliance gap — do not infer business context that isn't present.

### 1. Data protection and privacy (LGPD, GDPR, CCPA)
- Storage resources (databases, buckets, file shares) without encryption at rest using customer-managed keys
- Data resources created in regions that may violate data residency requirements (check region attributes)
- Missing data classification signals (no tags indicating data sensitivity level)
- Database resources without audit logging enabled
- Backup resources crossing regional boundaries without explicit configuration
- **Cross-resource**: PII-adjacent resources (databases, caches) without network isolation from public tiers

### 2. Audit and accountability (SOC2, ISO 27001)
- Missing CloudTrail/Activity Log/Audit Log for the account/subscription/project
- CloudTrail/audit logs without integrity validation (log file validation disabled)
- Log storage without immutability protections (missing Object Lock, retention policies)
- Missing centralized logging destination (logs scattered across individual resources)
- IAM actions not constrained by conditions (missing MFA requirement for sensitive operations)
- **AWS**: Missing `aws_cloudtrail` with `is_multi_region_trail = true`
- **Azure**: Missing diagnostic settings on key resources
- **GCP**: Missing organization-level audit log sink

### 3. Access control (PCI-DSS, HIPAA, NIST 800-53)
- Administrative/privileged access without MFA conditions in IAM policies
- Service accounts or roles with access to sensitive data without least-privilege scoping
- Missing network segmentation between cardholder/PHI data environments and general workloads
- Database resources accessible from public subnets (PCI-DSS requirement for network isolation)
- Missing encryption in transit for data resources (TLS requirement)
- **Cross-resource**: IAM policy allows broad access but attached to role used by internet-facing service

### 4. Business continuity (SOC2 A1, ISO 22301)
- Stateful resources without backup or point-in-time recovery
- Missing cross-region disaster recovery configuration for critical databases
- Single-region deployments for resources tagged as production
- Missing deletion protection on databases and critical storage
- Backup retention periods shorter than regulatory minimums (common: 7 days minimum, varies by framework)

### 5. Change management and drift
- Resources without `terraform` or `ManagedBy` tags (cannot prove IaC governance)
- Missing state locking configuration (risk of concurrent modifications)
- Sensitive resources without `lifecycle { prevent_destroy = true }`
- Provider versions unpinned (builds not reproducible = audit failure)

### Important notes
- Do NOT assume the workload's compliance scope — only flag when resource attributes CLEARLY indicate a gap
- If an `Environment` tag indicates `dev` or `staging`, lower the severity (compliance controls are less critical for non-production)
- Reference the specific framework principle where applicable (e.g., "PCI-DSS Req 3.4: Render PAN unreadable")

### Severity calibration for compliance
- **CRITICAL**: Active violation with data exposure risk (unencrypted PHI/PCI data, missing audit trail for production)
- **HIGH**: Missing required control for production workloads (no backup, no log integrity, no encryption)
- **MEDIUM**: Incomplete compliance posture (partial logging, weak but present access controls)
- **LOW**: Best-practice gaps that improve audit readiness but aren't strict violations
