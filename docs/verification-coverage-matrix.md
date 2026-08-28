# cis-aws-end-user-compute — verification coverage matrix

Phase C (verification-rigor sweep). Principle: **verify the technical state
wherever the platform can answer it; never accept a human attestation as proof
of a checkable fact.** This matrix makes the trust boundary auditable.

| Control | Disposition | Notes |
|---|---|---|
| C-2.10 maintenance mode | **VERIFY** | `directories[].workspace_creation_properties.enable_maintenance_mode` |
| C-2.15 directory SG ingress | **VERIFY** | `workspace_security_group_id` + `aws_security_group` |
| C-5.7 AppStream image age | **VERIFY** | `image_builders_older_than` |
| C-2.12 approved bundles | dual-mode | input-gated automation |
| **C-2.2 MFA** | **VERIFY (Phase C)** | RADIUS-MFA verified via `radius_settings` when `workspaces_require_radius_mfa: true`; AD-native MFA = documented residual |
| **C-2.5 NAT routing** | **VERIFY (in-profile)** | `aws_workspaces_egress_routing` joins each directory's `subnet_ids` → route table; flags any subnet with a public (igw) default route. Built in-profile per each_profile_stands_alone (no VPC-profile deferral). exec_validated:false. |
| **C-2.1 admin via IAM** | **VERIFY (in-profile)** | `aws_workspaces_admin_iam` scans customer-managed policies for broad `workspaces:*` admin on `Resource:*` (least-privilege). Built in-profile per each_profile_stands_alone (NOT deferred to foundations §1). exec_validated:false. |
| C-2.11 image CIS benchmark | attest (justified) | Image bake-time / golden-AMI scan — not assertable from the running directory. |
| C-4.1/4.2/4.4/4.5/4.6 WorkDocs | attest (justified) | **AWS announced WorkDocs deprecation 2025-04-25**; the WorkDocs SDK does not expose admin-identity / activity-feed / invite-policy state. Genuinely off-API. |

## Residual attestations — why unverifiable
- **C-2.11** — image content is decided at bake time; the running WorkSpace doesn't expose its golden-AMI provenance.
- **C-4.x (WorkDocs)** — deprecated service; no API for the asserted facts.

Each attestation keeps a `document_attestation` freshness floor.

## Note (no in-house scope)
No end-user-compute services run in-house here; these checks are
`exec_validated: false` and exist for consumers that do run them. Verification
logic must be validated against a
real deployment before being relied upon.
