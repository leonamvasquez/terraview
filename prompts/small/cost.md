Identify cost anti-patterns visible in the plan.

### Key checks

1. **Over-provisioning**: Instance types far larger than workload requires; excessive storage allocation without lifecycle policy
2. **Idle resources**: Resources created but not connected (orphaned EIPs, unattached EBS volumes, empty target groups)
3. **Missing reservations**: On-Demand instances for predictable long-running workloads (no Savings Plan signal)
4. **Data transfer**: Cross-AZ traffic patterns; missing VPC endpoints causing NAT gateway charges for S3/DynamoDB

### Severity

- **HIGH**: Waste >30% of projected cost, idle resources accumulating charges
- **MEDIUM**: Optimization opportunities, missing commitments
- **LOW**: Minor right-sizing suggestions
