# cis-aws-end-user-compute — verification coverage matrix

Phase C (verification-rigor sweep). Principle: **verify the technical state
wherever the platform can answer it; never accept a human attestation as proof
of a checkable fact.** This matrix makes the trust boundary auditable.

| Control | Disposition | Notes |
|---|---|---|
| C-2.10 maintenance mode | **VERIFY** | `directories[].workspace_creation_properties.enable_maintenance_mode` (#163) |
| C-2.15 directory SG ingress | **VERIFY** | `workspace_security_group_id` + `aws_security_group` (#163) |
| C-5.7 AppStream image age | **VERIFY** | `image_builders_older_than` (#163) |
| C-2.12 approved bundles | dual-mode | input-gated automation (#163) |
| **C-2.2 MFA** | **VERIFY (Phase C)** | RADIUS-MFA verified via `radius_settings` when `workspaces_require_radius_mfa: true`; AD-native MFA = documented residual |
| C-2.5 NAT routing | attest (verifiable — deferred) | **Verifiable** by joining directory `subnet_ids` → route tables → NAT-GW route. Needs a net-new EC2 route-table resource; tracked. Not shipped unvalidated. |
| C-2.1 admin via IAM | attest (cross-domain) | Verifiable only via an account-wide IAM-policy-graph analysis (who holds `workspaces:*`) — that's a **cis-aws-foundations §1 IAM concern**, not a WorkSpaces-API fact. Cross-referenced there. |
| C-2.11 image CIS benchmark | attest (justified) | Image bake-time / golden-AMI scan — not assertable from the running directory. |
| C-4.1/4.2/4.4/4.5/4.6 WorkDocs | attest (justified) | **AWS announced WorkDocs deprecation 2025-04-25**; the WorkDocs SDK does not expose admin-identity / activity-feed / invite-policy state. Genuinely off-API. |

## Residual attestations — why unverifiable
- **C-2.1** — account-wide IAM analysis belongs to the IAM/foundations profile; surfaced here only as the WorkSpaces-admin facet.
- **C-2.11** — image content is decided at bake time; the running WorkSpace doesn't expose its golden-AMI provenance.
- **C-4.x (WorkDocs)** — deprecated service; no API for the asserted facts.

Each attestation keeps a `document_attestation` freshness floor.

## Note (zero SPARC scope)
SPARC runs no WorkSpaces/WorkDocs/AppStream; these checks are `exec_validated: false`
and exist for non-SPARC consumers. Verification logic must be validated against a
real deployment before being relied upon.
