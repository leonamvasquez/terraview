Evaluate infrastructure for cost efficiency using FinOps principles.
Focus on waste that can be quantified and actioned — not theoretical savings.

### 1. Over-provisioning
- Instance types significantly larger than workload requires (e.g., `m5.4xlarge` for a simple API)
- Database instances with high compute but no performance indicators (multi-AZ xlarge for dev environment)
- Over-sized NAT gateways, VPN gateways, or load balancers for low-traffic workloads
- Memory/CPU over-allocation on container tasks (ECS task definition, Cloud Run, AKS pods)
- **Cross-resource check**: If the environment tag is `dev`/`staging`, flag production-tier sizing

### 2. Missing cost controls
- Resources without auto-scaling that could benefit from it (fixed instance count in ASG)
- Missing spot/preemptible instances for fault-tolerant workloads (batch processing, workers, CI/CD)
- On-demand instances for steady-state workloads that should use Reserved/Savings Plans/CUDs
- Missing S3/GCS lifecycle policies on log or temporary data buckets (storage grows unbounded)
- Missing DynamoDB auto-scaling or on-demand billing for variable workloads

### 3. Idle and orphaned resources
- Elastic IPs or static IPs not attached to any instance
- Load balancers with empty target groups
- EBS volumes or managed disks not attached to any instance
- VPN gateways or NAT gateways in VPCs with no private subnets
- Security groups with no attached network interfaces

### 4. Storage cost optimization
- GP2 volumes that should be GP3 (GP3 is cheaper with better baseline performance)
- S3 buckets using Standard storage class for infrequently accessed data (missing Intelligent-Tiering)
- Database snapshots without retention limits (unbounded snapshot costs)
- CloudWatch log groups without retention period (logs stored indefinitely)

### 5. Network transfer costs
- Cross-AZ traffic patterns (resources communicating across AZs incur data transfer costs)
- Missing VPC endpoints for high-volume S3/DynamoDB access (data transfer vs endpoint cost)
- Public IP usage on resources that only need private communication
- Cross-region replication without necessity (high transfer costs)

### 6. Environment-awareness
- Production-tier resources tagged as non-production (dev/staging with multi-AZ, large instances)
- Missing scheduled scaling (dev/staging resources running 24/7 when only needed during business hours)
- Development databases with deletion protection and multi-AZ enabled

### Severity calibration for cost
- **HIGH**: Significant monthly waste (>$500/month estimated), production-tier sizing in non-prod
- **MEDIUM**: Moderate waste (>$100/month), missing lifecycle policies on growing storage
- **LOW**: Minor optimization opportunities, GP2→GP3 migration, spot instance candidates
- **INFO**: Cost-aware positive patterns worth maintaining

## Example

Input context: `aws_db_instance.analytics_dev` with `instance_class = "db.r6g.4xlarge"`, `multi_az = true`, `deletion_protection = true`, tagged `Environment = "dev"`.

```json
{
  "severity": "HIGH",
  "category": "cost",
  "resource": "aws_db_instance.analytics_dev",
  "message": "Development database aws_db_instance.analytics_dev is sized as db.r6g.4xlarge with multi_az = true and deletion_protection = true — the Environment tag says 'dev' but the configuration is production-grade. On-demand pricing for this class multi-AZ is roughly $1,500/month; a dev database on db.t4g.medium single-AZ would be under $50/month.",
  "remediation": "Downgrade to db.t4g.medium (or smallest class passing the workload), set multi_az = false and deletion_protection = false for dev, and consider a scheduled stop/start outside of business hours.",
  "references": []
}
```
