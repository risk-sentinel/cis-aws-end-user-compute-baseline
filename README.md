# cis-aws-end-user-compute-baseline

InSpec / CINC Auditor profile validating AWS end-user compute against the
**CIS AWS End User Compute Services Benchmark v1.2.0** — 34 controls across
WorkSpaces, AppStream 2.0 and WorkDocs.

Targets **AWS Commercial** and **AWS GovCloud (non-DoD)**. Per-control partition
applicability is in [`partition_applicability.yml`](partition_applicability.yml)
and encoded as `tag applicable_partitions:`.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/cis-aws-end-user-compute-baseline
cd cis-aws-end-user-compute-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t aws:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

### Credentials

Standard AWS credential resolution. Read-only across the EUC surface:

```
workspaces:Describe*   appstream:Describe*   workdocs:Describe*
ds:DescribeDirectories  ec2:DescribeSecurityGroups  ec2:DescribeRegions
kms:DescribeKey         iam:GetRole
```

### What a first run looks like

Against a real account, scoped to one region, with the attestation URIs empty:

**34 controls, 35 results — roughly 23 passed / 1 failed / 11 skipped.**

**The skips are the point, not a fault.** This profile has the highest
attestation density in the estate — nine of its inputs are attestation URIs —
and with them empty those controls skip with a rationale rather than passing. If
you see far fewer than 35 results, that is a different problem and worth
investigating.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml).

| Group | Inputs |
|---|---|
| **Required** | `aws_partition` |
| **Scoping** | `applicable_services`, `scan_regions` |
| **Thresholds** | `approved_workspaces_bundles`, `workspaces_remote_access_ports`, `workspaces_require_radius_mfa`, `workdocs_inactive_threshold_days`, `appstream_image_max_age_days` |
| **Logging** | `logging_strategy`, `logging_requirements`, `logging_attestation_reference` |
| **Attestation** | four `euc_*_attestation_reference` strings, the `*_base` URIs, nine `c_*_attestation_uri` overrides |

**Nine attestation URIs is the defining feature of this profile.** WorkSpaces,
AppStream and WorkDocs expose relatively little through their APIs, and much of
what CIS asks about — image-pipeline governance, site configuration, MFA design
— is a documented decision rather than a queryable setting. Those controls skip
with a rationale until you point them at evidence. A mostly-skipped first run is
the profile telling you which documents it needs.

**`approved_workspaces_bundles` empty is not "all bundles approved".** It means
the control has nothing to check against and reports that.

---

## Controls

34 controls across three services:

| Service | Assesses |
|---|---|
| WorkSpaces | volume encryption, running mode, remote-access exposure, directory MFA, approved bundles, maintenance |
| AppStream 2.0 | fleet and image-builder network placement, image currency, session storage and clipboard policy |
| WorkDocs | sharing and external-collaboration posture, inactive users, audit logging |

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/cis-aws-end-user-compute-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-account
      profile_name: cis-aws-end-user-compute-v1.2.0
      profile_version: "0.1.0"
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/cis-aws-end-user-compute-baseline
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-account
      profile_name: cis-aws-end-user-compute-v1.2.0
      profile_version: "0.1.0"
```

An `include:` brings YAML and nothing else, which is why the logic lives in the
YAML rather than in a script an including project would never receive. The
templates are carried in this repository on purpose: clone it or include it and
you have the entire pipeline, with nothing else to install.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump. On 3.5.1, `@1` and `@2` are byte-identical.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.
An audit chain where every field is self-asserted is a story.

Schema authority: [dev-sec-ops-baseline#33](https://github.com/risk-sentinel/dev-sec-ops-baseline/issues/33).

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: cis-aws-end-user-compute-v1.2.0
    git: https://github.com/risk-sentinel/cis-aws-end-user-compute-baseline.git
    tag: v0.1.5
```

Then `include_controls 'cis-aws-end-user-compute-v1.2.0'` and supply your own inputs. Input overrides
reach the depended profile's controls, so your values win without editing
anything here.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real target before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
