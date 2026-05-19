# AWS End User Compute Services CIS Baseline

InSpec / CINC Auditor profile validating an AWS account against **CIS AWS End User Compute Services Benchmark v1.2.0**.

## Scope

- **AWS Commercial** (`aws_partition=aws`) — primary target.
- **AWS GovCloud non-DoD** (`aws_partition=aws-us-gov`) — primary target.
- Azure and other cloud providers — out of scope.

The benchmark covers four AWS services:

| CIS section | Service | `applicable_services` value |
|---|---|---|
| 2 (18 controls) | Amazon WorkSpaces — desktop VDI | `workspaces` |
| 3 (1 control) | AWS WorkSpaces Web — browser portal | `workspaces_web` |
| 4 (8 controls) | Amazon WorkDocs | `workdocs` |
| 5 (7 controls) | AWS AppStream 2.0 | `appstream` |

Consumers that don't operate any of these services can leave `applicable_services` empty — every section auto-skips via `only_if`. Consumers running specific services list those (e.g., `applicable_services: [appstream, workdocs]`) and the relevant sections execute against the four local libraries (`aws_workspaces_inventory`, `aws_workspaces_web_inventory`, `aws_workdocs_inventory`, `aws_appstream_inventory`).

Per-control partition applicability lives in `partition_applicability.yml` and is mirrored on each control via `tag applicable_partitions: [...]`.

## Running Locally

Prerequisites: Docker. Vendor once to pull the `inspec-aws` resource pack:

```bash
docker pull risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1

docker run --rm -v "$PWD:/src" risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 \
  vendor /src/profiles/cis-aws-end-user-compute --overwrite
```

Execute against AWS Commercial:

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-aws-end-user-compute \
  --input-file /src/profiles/cis-aws-end-user-compute/inputs.yml \
  --reporter cli json:/src/hdf.json
```

GovCloud follows the same shape with `aws_partition=aws-us-gov` + `us-gov-west-1` region.

## Portability

| Input | Default | When to override |
|---|---|---|
| `aws_partition` | `aws` | Set to `aws-us-gov` for GovCloud non-DoD. |
| `applicable_services` | `[]` (all sections) | Allowlist: `workspaces`, `workspaces_web`, `workdocs`, `appstream`. Sections out of scope auto-skip. |

### Example: consumer not running any end-user-compute service

```yaml
aws_partition: aws
# applicable_services intentionally unset — consumer doesn't operate
# any of these services. Every control auto-skips with the pending-
# resource rationale; the profile is shipped for future adopters.
```

### Example: consumer running WorkSpaces + AppStream

```yaml
aws_partition: aws
applicable_services:
  - workspaces
  - appstream
```

## NIST 800-53 Tagging

Every control carries `tag nist: [...]` resolved at scaffold time from the XCCDF's DISA CCI identifiers via Heimdall's `CciNistMappingData.ts`. Same provenance chain as the other AWS-side profiles in this repo.

## Regenerating From XCCDF

```bash
python3 tools/xccdf_to_inspec/scaffold.py \
  --xccdf benchmarks/xccdf/cis_aws_end_user_compute_services_benchmark_v120.xml \
  --cci-map /path/to/heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts \
  --output profiles/cis-aws-end-user-compute \
  --profile-name cis-aws-end-user-compute \
  --profile-title "AWS End User Compute Services CIS Baseline" \
  --supports-platform aws
```

## Status

All 34 controls filled (issue #15) and all `planned` controls closed via the v0.1.0 release-prep sweep. Each control carries a `tag implementation_status:` mapped to OSCAL's native vocabulary — see the [Control Classification Guide](../../docs/dev/Control_Classification_Guide.md).

### Coverage distribution

| Type | `implementation_status` | Count |
|---|---|---|
| **Automated** | `implemented` | 15 |
| **Attestation** | `alternative` | 19 |
| **Pending-resource** | `planned` | 0 |

The 15 automated controls run via four custom libraries:
- `aws_workspaces_inventory` — §2 (Amazon WorkSpaces; built into stock cinc-auditor).
- `aws_workspaces_web_inventory` — §3 (WorkSpaces Web; needs `aws-sdk-workspacesweb` gem).
- `aws_workdocs_inventory` — §4 (WorkDocs; needs `aws-sdk-workdocs` gem).
- `aws_appstream_inventory` — §5 (AppStream 2.0; needs `aws-sdk-appstream` gem).

The §3 / §4 / §5 gems are NOT bundled in upstream `cincproject/auditor`. Consumers run against the **Risk Sentinel extended cinc-auditor image** ([your CI image-bake tracker](https://example.invalid/cross-repo-issue)) — when it lands. Until then, the §3 / §4 / §5 controls fall back to attestation rationale at exec time via the `connection_error` accessor (per [`docs/dev/Vendored_Resource_Gaps.md` §5](../../docs/dev/Vendored_Resource_Gaps.md#5-connection-precheck-describe-for-network-crossing-resources)). Stock cinc-auditor still produces a clean HDF — every control either runs (with extended image) or skips with documented attestation rationale (with stock image). No silent failures.

### Per-section breakdown

| Section | Service | Controls | Implemented | Alternative | Planned |
|---|---|---|---|---|---|
| 2 | Amazon WorkSpaces | 18 | 8 | 10 | 0 |
| 3 | AWS WorkSpaces Web | 1 | 1 | 0 | 0 |
| 4 | Amazon WorkDocs | 8 | 3 | 5 | 0 |
| 5 | AWS AppStream 2.0 | 7 | 3 | 4 | 0 |

### `aws_workspaces_inventory` custom resource

`libraries/aws_workspaces_inventory.rb` wraps the AWS WorkSpaces Ruby client and exposes offender-list helpers:

| Helper | CIS control |
|---|---|
| `workspaces_unencrypted_volumes` | 2.3 |
| `directories_not_in_dedicated_vpc` | 2.4 |
| `directories_with_web_access_enabled` | 2.6 |
| `directories_without_ip_group_restriction` | 2.7 |
| `directories_without_fips_endpoint` | 2.16 |
| `directories_with_weak_radius_protocol` | 2.18 |
| `workspaces_in_unhealthy_state` | 2.14 |
| `images_older_than(days)` | 2.13 |

Each method paginates the relevant `describe_*` call and returns a list of offending IDs (empty list = passing).

### Local libraries

Four service-specific custom resources cover §2 / §3 / §4 / §5:

| Library | Section | Service client | Key accessors |
|---|---|---|---|
| `aws_workspaces_inventory.rb` | §2 | `Aws::WorkSpaces::Client` (built-in) | `workspaces_unencrypted_volumes`, `directories_not_in_dedicated_vpc`, `directories_with_web_access_enabled`, `directories_without_ip_group_restriction`, `directories_without_fips_endpoint`, `directories_with_weak_radius_protocol`, `workspaces_in_unhealthy_state`, `images_older_than(days)` |
| `aws_workspaces_web_inventory.rb` | §3 | `Aws::WorkSpacesWeb::Client` (needs `aws-sdk-workspacesweb`) | `portals`, `portals_without_user_access_logging`, `connection_error` |
| `aws_workdocs_inventory.rb` | §4 | `Aws::WorkDocs::Client` (needs `aws-sdk-workdocs`) | `organizations`, `organizations_without_ip_allowlist`, `organizations_allowing_public_share`, `inactive_users`, `connection_error` |
| `aws_appstream_inventory.rb` | §5 | `Aws::AppStream::Client` + `Aws::EC2::Client` (needs `aws-sdk-appstream`) | `fleets`, `image_builders`, `fleets_without_vpc_config`, `image_builders_without_vpc_config`, `vpcs_without_appstream_endpoint`, `fleets_using_default_internet_access`, `connection_error` |

Each per-region client is instantiated directly (rather than via the inspec-aws class-keyed cache) so multi-region scans don't serialize through one client. Each library handles `AccessDenied` / `NoSuch...` per-call to fail-fast on a missing IAM permission rather than silently producing empty results. The `connection_error` accessor lets the calling control fall back to attestation cleanly when the SDK gem is missing (stock cinc-auditor) or AccessDenied is returned at the partition / account level.

### `exec_validated` semantics

Every control carries `tag exec_validated: false`. cinc-auditor `check` passes; live exec validation depends on a consumer running these services. The flag flips when a consumer scan exercises the implementations.

## See also

Top-level `README.md` for overall repo state and the sub-issue tracker for per-profile progress.
