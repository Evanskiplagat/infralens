# InfraLens

InfraLens is a Go command-line tool for discovering AWS resources, mapping their relationships, reporting possible exposure risks, and comparing infrastructure scans over time.

It runs locally with read-only AWS credentials and stores scan data in SQLite. Output is available in formats suitable for terminal use, scripts, CI/CD pipelines, and graph visualisation.

## Why a CLI

The CLI runs within the caller's AWS credential scope and does not require a hosted service. Its structured output can be passed to tools such as `jq`, used in a CI check, or compared between scans.

## Target Capabilities

```text
infralens scan      Discover AWS resources across regions using read-only credentials
infralens graph      Build and inspect resource relationships
infralens findings   Detect exposure and risky topology; emit table, JSON, SARIF, or Markdown
infralens diff       Compare two scans over time
infralens export     Emit JSON, CSV, or Graphviz/DOT
infralens scans      List stored scans
infralens rules      List the built-in rules and how to fix each one
infralens serve      (planned) local read-only viewer — see docs/roadmap.md
```

See [docs/cli.md](docs/cli.md) for full command usage and examples.

## What Makes It More Than a Lister

- **Topology-aware findings.** An instance with a public IP and an open security group is only as exposed as its route to the internet. InfraLens traces instance, subnet, route table (including the VPC's main table) and internet gateway, raises severity when the path is confirmed, lowers it when the subnet has no route, and prints the evidence: `internet -> igw-1 -> vpc-1 -> rtb-1 -> subnet-1 -> i-1`. When route data is missing it says so rather than assuming safety.
- **Eight rules with remediation.** Open security groups (with all-traffic escalated to critical), public S3 buckets, exposed instances, IMDSv1 on instances with credentials, unencrypted EBS volumes, S3 Block Public Access gaps, unused security groups, and workloads in the default VPC. Every rule explains what it detects and how to fix it; see [docs/rules.md](docs/rules.md).
- **Policy as code.** Disable rules, re-rank severities, and waive individual findings with a reason, an owner and an expiry date. Expired waivers resurface their findings and warn; stale waivers are called out. See [docs/policy.md](docs/policy.md).
- **CI-native output.** SARIF 2.1.0 for code-scanning platforms, Markdown for job summaries and pull-request comments, JSON for scripts, and `--fail-on` / `--baseline` gates that fail only on new or worsened risk. A ready-to-adapt workflow is in [examples/github-actions](examples/github-actions/infralens-scan.yml).
- **Multi-region, concurrent, resilient discovery.** Regions are scanned in parallel with bounded concurrency; throttling is retried with exponential backoff and jitter; and when a region fails, what the others found is kept as a `partial` scan instead of being discarded.

## Repository Layout

```text
cmd/infralens/     CLI entrypoint (main.go)
internal/
  cli/             Command parsing and wiring
  config/          Config resolution (file, env, flags)
  awsdiscovery/    Read-only AWS SDK calls, isolated from the rest of the codebase
  normalize/       Raw AWS shapes -> internal resource/edge model
  graph/           In-memory relationship graph and traversal
  findings/        Rule engine, rule catalog, and internet-path analysis
  policy/          Rule tuning and expiring waivers from a policy file
  report/          SARIF and Markdown renderers
  storage/         Store interface + SQLite implementation
  export/          JSON, CSV, and DOT serializers
  diff/             Scan comparison logic
  resource/        Shared domain types (Resource, Edge, Scan)
docs/              Architecture, CLI spec, rules, policy, security notes, roadmap
examples/          Sample policy file and GitHub Actions workflow
frontend/          Deprecated React shell; not part of the product (see frontend/README.md)
terraform/         Read-only discovery IAM role module
demo/              Fixtures and sample scan data
```

## Quick Start

Requires Go 1.23+ and read-only AWS credentials (a named profile or the standard SDK credential chain).

```bash
go build -o bin/infralens ./cmd/infralens

./bin/infralens scan --profile my-readonly-profile --regions us-east-1,eu-west-1
./bin/infralens findings --severity high
./bin/infralens findings --policy infralens.policy.json --format sarif --out infralens.sarif
./bin/infralens graph --format dot --out graph.dot
./bin/infralens diff --from <scan-id> --to latest
```

Scan history is stored locally in a SQLite file (`infralens.db` by default; override with `--db` or `INFRALENS_DB_PATH`).

## Status

The repository contains the Go module, package structure, and command surface described above. Validate a local checkout with:

```bash
go mod tidy
go build ./...
go vet ./...
go test ./...
```

See [docs/roadmap.md](docs/roadmap.md) for what's implemented versus planned.

## Security

InfraLens is designed to run with least-privilege, read-only AWS credentials. See [docs/security.md](docs/security.md).
