# CLI Command Spec

All commands accept `--db <path>` to override the SQLite database location (default `infralens.db`, or `INFRALENS_DB_PATH`/config file) and `--log-level <debug|info|warn|error>` to control stderr operational logs. Commands that talk to AWS additionally accept `--profile` and `--region`.

## `infralens scan`

Discovers AWS resources with read-only credentials, normalizes them, evaluates findings, and persists everything as a new scan.

```text
infralens scan [--profile NAME] [--region REGION | --regions R1,R2,...] [--concurrency N]
               [--max-attempts N] [--allow-partial] [--db PATH]
```

```bash
infralens scan --profile prod-readonly --region us-east-1
# scan 20260820T140512Z complete: 42 resources, 61 edges, 3 findings

# Several regions in parallel
infralens scan --regions us-east-1,eu-west-1,ap-southeast-2 --concurrency 6
```

Currently discovers: VPCs, subnets, route tables (including the main table), internet gateways, security groups (including which groups reference each other), EC2 instances (including IMDS settings and instance profiles), EBS volumes (with encryption status), and S3 buckets (with public-access status and Block Public Access settings). See [docs/roadmap.md](roadmap.md) for planned service coverage.

### Multi-region scans, retries and partial results

`--regions` scans each listed region in parallel, up to `--concurrency` tasks at a time (default 4). Account-wide services such as S3 run once per scan, not once per region. Results are merged in a fixed order, so a scan of the same account is identical no matter how tasks were scheduled.

Throttling and transient service errors are retried with exponential backoff and jitter, up to `--max-attempts` tries per task (default 3, counting the first). Permission and validation errors are not retried because they would fail identically again.

If some tasks still fail, everything the others discovered is kept and the scan is recorded with status `partial` instead of being thrown away. By default the command then exits non-zero after saving the results, so CI notices a region it could not read; pass `--allow-partial` to accept partial results. If every task fails, the scan is recorded as `failed`. Partial scans cannot be used as `findings --baseline` targets or baselines, because missing data would look like fixed findings.

The scan is stored with the AWS account ID, which `findings --baseline` uses to refuse comparing scans from different accounts.

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
infralens findings [--scan ID|latest] [--baseline ID] [--policy FILE]
                   [--severity info|low|medium|high|critical] [--fail-on info|low|medium|high|critical]
                   [--format table|json|sarif|markdown] [--out FILE] [--db PATH]
```

```bash
# CI gate: fail the pipeline if any high or critical finding exists
infralens findings --severity high --fail-on high --format json

# Fail only for new or worsened high-severity findings since a known scan
infralens findings --baseline 20260801T090000Z --fail-on high --format json

# Apply team policy, publish to code scanning, and summarize in a pull request
infralens findings --policy infralens.policy.json --format sarif --out infralens.sarif
infralens findings --policy infralens.policy.json --format markdown >> "$GITHUB_STEP_SUMMARY"
```

Severities, from least to most urgent, are `info`, `low`, `medium`, `high` and `critical`. Findings are ordered most severe first, then by rule and resource, so output is stable from run to run.

### Output formats

- `table` (default) is for people at a terminal.
- `json` is the stable machine contract: an array of findings, `[]` when there are none.
- `sarif` writes a SARIF 2.1.0 log for code-scanning platforms and security tooling. Each rule carries its description and remediation; each result has a stable fingerprint derived from the rule and resource, so alerts are tracked across scans; and findings waived by a policy are included with a SARIF suppression holding the reason. SARIF needs a file location, so resources appear at a virtual path of the form `aws/<account-id>/<resource-id>`; the resource ID is also given as a logical location.
- `markdown` writes a summary with severity counts, the most severe findings (capped at 100 rows to stay under GitHub's comment size limit), and a "How to fix" section with one block per rule that fired.

`--out FILE` writes the report to a file instead of stdout.

### Policy

`--policy FILE` applies a [policy file](policy.md) before anything else: disabled rules are dropped, severity overrides are applied, and waived findings are removed (with warnings for expired or stale waivers). With `--baseline`, the policy is applied to both scans before they are compared.

`--baseline` compares findings by rule ID and resource ID. Existing findings are omitted unless their severity increased; title and description changes alone do not count. Both scans must be complete, distinct, and cover the same AWS account and regions. The baseline must be an explicit scan ID, not `latest`.

`--severity` filters displayed output only. `--fail-on` checks all findings selected by the baseline comparison (or all scan findings when no baseline is given), even if the display filter hides them. Empty JSON results are `[]`.

Built-in rules are listed in [rules.md](rules.md), or with `infralens rules`.

## `infralens rules`

Lists the built-in findings rules, or explains one in detail. It needs no AWS credentials or database.

```text
infralens rules [--id RULE] [--format table|json]
```

```bash
infralens rules
infralens rules --id internet_exposed_instance
infralens rules --format json | jq -r '.[].ID'
```

Rule IDs are stable across releases, so policies and CI filters can rely on them.

## `infralens version`

Prints the version. Release builds stamp it with `-ldflags "-X infralens/internal/cli.Version=v1.2.3"`; it is also recorded in SARIF output.

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
- Exit code is non-zero on any error (AWS call failure, unknown scan ID, bad flag). `findings --fail-on <severity>` also exits non-zero when matching findings exist, so it can act as a CI gate without `jq`. `scan` exits non-zero when it saves a partial scan unless `--allow-partial` is given.
- A ready-to-adapt GitHub Actions workflow lives in [examples/github-actions/infralens-scan.yml](../examples/github-actions/infralens-scan.yml).
