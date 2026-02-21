When reviewing for standards compliance, focus on:

1. **Tagging**: All resources should have at minimum: Environment, Team/Owner, Project/Application, and ManagedBy tags.
2. **Naming**: Resources should follow a consistent naming convention (e.g., {project}-{environment}-{resource_type}-{identifier}).
3. **Versioning**: S3 buckets should have versioning enabled. Lambda functions should use specific runtime versions, not latest.
4. **Lifecycle**: Resources should have appropriate lifecycle policies. S3 objects should have expiration rules where applicable.
5. **Monitoring**: Resources should have associated CloudWatch alarms or monitoring configured.
6. **Documentation**: Complex modules should have descriptions on variables and outputs.

Only flag deviations that could cause operational issues. Minor cosmetic naming differences should be INFO level at most.
