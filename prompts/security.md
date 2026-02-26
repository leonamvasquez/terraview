Focus on security risks that require CONTEXTUAL REASONING — not simple attribute checks that static scanners already handle.

### 1. Network exposure chains
- Security groups/NSGs allowing 0.0.0.0/0 ingress on sensitive ports (22, 3389, 3306, 5432, 6379, 27017, 9200, 9300)
- Resources with public IPs in subnets that should be private
- Load balancers forwarding to targets without TLS termination
- **Cross-resource**: Security group attached to multiple unrelated services (blast radius)
- **AWS**: Missing VPC endpoints for S3/DynamoDB accessed from private subnets
- **Azure**: NSG rules without service tags, missing Private Link for PaaS services
- **GCP**: Firewall rules with source range 0.0.0.0/0, missing IAP for SSH/RDP

### 2. IAM and identity
- Policies with wildcard actions (`*`) or resources (`*`) — especially on data services (S3, DynamoDB, RDS, KMS)
- IAM roles assumed by multiple unrelated services (shared identity = lateral movement)
- Missing permission boundaries on roles that can create other roles
- Service accounts with user-level access or roles bound at organization/project level
- **AWS**: Missing `aws_iam_policy_boundary`, roles without `sts:ExternalId` for cross-account
- **Azure**: Contributor/Owner at subscription scope, missing Managed Identity (using service principal keys)
- **GCP**: `roles/editor` or `roles/owner` on service accounts, missing Workload Identity

### 3. Encryption and data protection
- Storage without encryption (but only flag if KMS/CMK is missing — default encryption may be acceptable)
- In-transit encryption gaps: internal service-to-service traffic without TLS
- KMS key policies allowing broad access, keys without rotation enabled
- Secrets hardcoded in resource attributes (passwords, tokens, connection strings)
- **Cross-resource**: Database encrypted but application connecting via non-TLS endpoint

### 4. Logging and detection
- Resources without audit logging (CloudTrail, Activity Log, Audit Log)
- Missing VPC Flow Logs, WAF logs, or access logs on public-facing resources
- Log destinations without encryption or retention policies
- **Cross-resource**: Logging exists but ships to a bucket/workspace that is publicly accessible or has no lifecycle policy

### 5. Zero-trust gaps
- Resources relying on network position instead of identity for access control
- Private resources accessible via overly broad VPN/peering rules
- Missing WAF on internet-facing application endpoints
- Secrets in environment variables instead of secrets manager references

### Severity calibration for security
- **CRITICAL**: Direct path to data exfiltration or account takeover (IAM `*:*`, public database, hardcoded secrets)
- **HIGH**: Significant attack surface expansion (SSH to internet, missing encryption on PII, shared IAM across trust boundaries)
- **MEDIUM**: Defense-in-depth gap (missing flow logs, no WAF, default encryption instead of CMK)
- **LOW**: Hardening opportunity (minor port exposure, overly broad but scoped policy)
