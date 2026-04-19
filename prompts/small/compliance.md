Check regulatory compliance patterns visible across resources.

### Key checks

1. **Audit trails**: Missing CloudTrail/Activity Log/Audit Log on data-holding resources; log retention below regulatory minimum
2. **Data residency**: Resources deployed in regions outside declared compliance boundary
3. **Encryption at rest**: Databases/storage without encryption where PII/PHI is likely (flag if resource names suggest patient, payment, user data)
4. **Access control**: No MFA condition on privileged IAM actions; missing resource-based policies on sensitive storage

### Frameworks

- **SOC2**: Encryption, access control, audit logging, availability
- **PCI-DSS**: Cardholder data isolation, encryption, logging
- **HIPAA/HITECH**: PHI encryption, audit trails, access control
- **LGPD**: Brazilian data residency and subject rights controls

### Severity

- **CRITICAL**: Clear regulatory violation (unencrypted PHI storage, no audit log on PCI scope)
- **HIGH**: Likely violation pending context confirmation
- **MEDIUM**: Gap that must be addressed before audit
- **LOW**: Best-practice alignment
