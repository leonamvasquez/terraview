Evaluate infrastructure architecture using cloud Well-Architected Framework principles.
Focus on patterns that require REASONING about the overall design — not single-resource checks.

### 1. Resilience and high availability
- Stateful resources (databases, caches, queues) deployed in a single AZ without failover
- Compute workloads without auto-scaling or health checks
- Missing multi-region or cross-zone redundancy for critical paths
- Load balancers pointing to a single target or single AZ target group
- **Cross-resource**: Application depends on a single RDS instance without read replica, yet has auto-scaling compute
- **AWS**: Missing `multi_az` on RDS/ElastiCache, ECS services with `desired_count: 1`
- **Azure**: Single-instance VMs without Availability Set/Zone, missing zone-redundant App Service
- **GCP**: Regional resources using single-zone, Cloud SQL without HA configuration

### 2. Blast radius and isolation
- Changes to shared resources (VPC, IAM roles, security groups) that propagate to many dependents
- Monolithic security groups attached to heterogeneous workloads
- Shared state files or terraform workspaces mixing prod/non-prod resources
- Deletion of resources that will cascade (VPC → subnets → ENIs → instances)
- Missing `lifecycle { prevent_destroy = true }` on stateful resources

### 3. Scaling patterns
- Fixed instance counts without ASG/VMSS/MIG policies
- Databases without read replicas when compute layer auto-scales
- Missing connection pooling between scaled compute and fixed-capacity database
- Queue consumers without auto-scaling tied to queue depth
- **Anti-pattern**: Auto-scaling compute → fixed-capacity database → connection exhaustion

### 4. Network architecture
- Resources in default VPC/VNet/network instead of purpose-built network
- Missing private subnets for backend services (databases, caches, internal APIs)
- Public subnets without NAT gateway for outbound traffic from private subnets
- Missing VPC peering or private connectivity between tiers
- DNS resolution gaps (missing private hosted zones, incorrect resolver rules)
- **Anti-pattern**: Flat network topology where all resources share a single subnet

### 5. Data protection and lifecycle
- Stateful resources without backup/snapshot policies
- Missing point-in-time recovery for databases
- Storage without lifecycle policies (unbounded growth)
- Deletion of stateful resources without `skip_final_snapshot` set to false
- Missing cross-region replication for disaster recovery requirements
- **Cross-resource**: S3 lifecycle rule deletes objects that another service depends on

### 6. Observability gaps
- Compute/database resources without CloudWatch/Monitor/Monitoring alarms attached
- Missing health checks on load balancer targets
- No distributed tracing instrumentation for microservice architectures
- Log groups without retention policies (cost + compliance risk)

### Severity calibration for architecture
- **CRITICAL**: Single point of failure for stateful production resources, cascade deletion risk
- **HIGH**: Missing HA for databases, no auto-scaling on production compute, flat network
- **MEDIUM**: Over-provisioned resources, missing observability, suboptimal scaling strategy
- **LOW**: Minor topology improvements, cost-related architecture changes
