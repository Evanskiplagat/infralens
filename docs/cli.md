# CLI Command Spec

All commands accept `--db <path>` to override the SQLite database location (default `infralens.db`, or `INFRALENS_DB_PATH`/config file) and `--log-level <debug|info|warn|error>` to control stderr operational logs. Commands that talk to AWS additionally accept `--profile` and `--region`.

## `infralens scan`

Discovers AWS resources with read-only credentials, normalizes them, evaluates findings, and persists everything as a new scan.

```text
infralens scan [--profile NAME] [--region REGION] [--db PATH]
```

```bash
infralens scan --profile prod-readonly --region us-east-1
# scan 20260820T140512Z complete: 42 resources, 61 edges, 3 findings
```

Currently discovers: VPCs, subnets, route tables, internet gateways, security groups, EC2 instances, and S3 buckets (with public-access status). See [docs/roadmap.md](roadmap.md) for planned service coverage.

## `infralens scans`

Lists stored scans, most recent first.

```text
infralens scans [--db PATH]
```

## `infralens graph`

Builds the resource graph for a scan and prints or exports it.

```text
infralens graph [--scan ID|latest] [--resource ID] [--depth N] [--format text|json|dot] [--out FILE] [--db PATH]
```

```bash
infralens graph --scan latest --format dot --out graph.dot
dot -Tpng graph.dot -o graph.png

# Inspect an instance and resources up to two relationships away
infralens graph --resource ec2_instance/i-123 --depth 2 --format json
```

`--resource` accepts the normalized `ID` shown in JSON graph/export output. It selects that resource and its neighbors, following both incoming and outgoing relationships. `--depth` defaults to 1; use 0 to select only the resource. All relationships between selected resources are included with their original directions. This shows structural relationships, not proof of network reachability.

Without `--resource`, the full graph is returned. An unknown resource, a negative depth, or `--depth` without `--resource` is an error. The selection applies to text, JSON, and DOT output.

## `infralens findings`

Evaluates (or, more precisely, retrieves the findings evaluated at scan time for) a scan's exposure and topology rules.

```text
infralens findings [--scan ID|latest] [--baseline ID] [--severity info|low|medium|high] [--fail-on info|low|medium|high] [--format table|json] [--db PATH]
```

```bash
# CI gate: fail the pipeline if any high-severity finding exists
infralens findings --severity high --fail-on high --format json

# Fail only for new or worsened high-severity findings since a known scan
infralens findings --baseline 20260801T090000Z --fail-on high --format json
```

`--baseline` compares findings by rule ID and resource ID. Existing findings are omitted unless their severity increased; title and description changes alone do not count. Both scans must be complete, distinct, and cover the same AWS account and regions. The baseline must be an explicit scan ID, not `latest`.

`--severity` filters displayed output only. `--fail-on` checks all findings selected by the baseline comparison (or all scan findings when no baseline is given), even if the display filter hides them. Empty JSON results are `[]`.

Built-in rules: `open_security_group`, `public_s3_bucket`, `internet_exposed_instance`. See [internal/findings/rules.go](../internal/findings/rules.go).

## `infralens diff`

Compares two scans' resources, with optional relationship comparison and a CI gate for infrastructure changes.

```text
infralens diff --from ID [--to ID|latest] [--include-edges] [--fail-on-change] [--format table|json] [--out FILE] [--db PATH]
```

```bash
infralens diff --from 20260801T090000Z --to latest --format json

# Save a report and fail CI if resources or relationships changed
infralens diff --from 20260801T090000Z --include-edges --fail-on-change --format json --out drift.json
```

`--include-edges` reports added and removed relationships, including changes between otherwise unchanged resources. JSON retains the existing resource fields and adds an `Edges` object with `Added` and `Removed` arrays when this flag is set. Changing a relationship's type or endpoints appears as a removal and an addition.

`--fail-on-change` exits non-zero after writing the report if resources were added, removed, or changed. Relationship changes also trigger this gate when `--include-edges` is enabled. With no changes, the command succeeds. `--out` saves either output format to a file; otherwise the report goes to stdout.

## `infralens export`

Exports a full scan (scan metadata, resources, edges, findings) for JSON, or resources only for CSV/DOT.

```text
infralens export [--scan ID|latest] [--format json|csv|dot] [--out FILE] [--db PATH]
```

```bash
infralens export --format csv --out resources.csv
infralens export --format json | jq '.findings'
```

## `infralens serve` (planned)

Reserved as the future extension point for a local, read-only web viewer over stored scans. Not implemented; see [docs/roadmap.md](roadmap.md). Currently exits with an error pointing here.

## Global Conventions

- Every command that reads scan data accepts `--scan latest` (the default) to mean "most recently started scan."
- `--format json` output is stable, indented JSON intended for `jq`/scripting; it is the contract automation should depend on, not the table/text output.
- Exit code is non-zero on any error (AWS call failure, unknown scan ID, bad flag). `findings --fail-on <severity>` also exits non-zero when matching findings exist, so it can act as a CI gate without `jq`.
