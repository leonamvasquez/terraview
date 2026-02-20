When reviewing for security issues, focus on:

1. **Network Exposure**: Security groups or firewall rules allowing 0.0.0.0/0 ingress, especially on sensitive ports (22, 3389, 3306, 5432, 6379, 27017)
2. **Encryption**: S3 buckets, EBS volumes, RDS instances, and other storage without encryption at rest. Load balancers without TLS.
3. **IAM**: Policies using wildcard (*) actions or resources. Overly permissive roles. Missing least-privilege boundaries.
4. **Secrets**: Hardcoded passwords, tokens, or keys in resource configurations.
5. **Public Access**: S3 buckets with public ACLs, RDS instances publicly accessible, EC2 instances with public IPs in private subnets.
6. **Logging**: Missing CloudTrail, VPC Flow Logs, or access logging on load balancers and S3 buckets.
7. **Root Account**: Any usage of root credentials or access keys.

Severity guide:
- CRITICAL: Direct data exposure risk or full account compromise (e.g., IAM wildcard on all resources)
- HIGH: Significant attack surface expansion (e.g., SSH open to internet)
- MEDIUM: Missing defense-in-depth layer (e.g., missing encryption on non-sensitive bucket)
- LOW: Minor hardening opportunity
