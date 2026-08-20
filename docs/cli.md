# CLI Command Spec

All commands accept `--db <path>` to override the SQLite database location (default `infralens.db`, or `INFRALENS_DB_PATH`/config file). Commands that talk to AWS additionally accept `--profile` and `--region`.

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
infralens graph [--scan ID|latest] [--format text|json|dot] [--out FILE] [--db PATH]
```

```bash
infralens graph --scan latest --format dot --out graph.dot
dot -Tpng graph.dot -o graph.png
```

## `infralens findings`

Evaluates (or, more precisely, retrieves the findings evaluated at scan time for) a scan's exposure and topology rules.

```text
infralens findings [--scan ID|latest] [--severity info|low|medium|high] [--format table|json] [--db PATH]
```

```bash
# CI gate: fail the pipeline if any high-severity finding exists
infralens findings --severity high --format json | jq -e 'length == 0'
```

Built-in rules: `open_security_group`, `public_s3_bucket`, `internet_exposed_instance`. See [internal/findings/rules.go](../internal/findings/rules.go).

## `infralens diff`

Compares two scans' resources.

```text
infralens diff --from ID [--to ID|latest] [--format table|json] [--db PATH]
```

```bash
infralens diff --from 20260801T090000Z --to latest --format json
```

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
- Exit code is non-zero on any error (AWS call failure, unknown scan ID, bad flag). `findings --severity high` does **not** itself fail on findings — pipe its JSON output through `jq` (as above) to turn findings into a CI gate.
