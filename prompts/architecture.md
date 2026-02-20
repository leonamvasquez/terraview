When reviewing architecture, focus on:

1. **High Availability**: Resources in a single AZ without redundancy. Missing multi-AZ for databases. No auto-scaling configured.
2. **Scaling**: Fixed instance counts without scaling policies. Under-provisioned resources.
3. **Networking**: Missing VPC isolation. Resources in default VPC. Missing private subnets for backend services.
4. **State Management**: Resources that should be managed together but are split. Circular dependencies.
5. **Cost Efficiency**: Over-provisioned instances. Resources that could use reserved or spot capacity.
6. **Data Protection**: Missing backup policies. No point-in-time recovery for databases. Missing lifecycle policies for storage.

Only flag architecture issues that represent real operational risk, not theoretical improvements.
