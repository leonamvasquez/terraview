Focus on security risks requiring cross-resource reasoning — not single-resource checks scanners already handle.

### Key checks

1. **Network exposure**: Security groups/NSGs with 0.0.0.0/0 on sensitive ports (22, 3389, 3306, 5432); public IPs in private subnets
2. **IAM**: Wildcard actions/resources on data services (S3, DynamoDB, RDS); shared roles across unrelated services; missing permission boundaries
3. **Encryption gaps**: Database encrypted but application connecting via non-TLS endpoint; KMS keys without rotation
4. **Logging**: Public-facing resources without access logs; log buckets publicly accessible

### Severity

- **CRITICAL**: Direct data exfiltration path (IAM `*:*`, public database, hardcoded secrets)
- **HIGH**: SSH to internet, missing PII encryption, shared IAM across trust boundaries
- **MEDIUM**: Missing flow logs, no WAF on public endpoint
- **LOW**: Minor hardening opportunities
