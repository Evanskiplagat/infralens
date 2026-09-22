# Roadmap

## Phase 1 — CLI foundation (this repository, current state)

- Go module, package layout, and command surface (`scan`, `graph`, `findings`, `diff`, `export`, `scans`, `serve` stub) as described in [architecture.md](architecture.md) and [cli.md](cli.md).
- Discovery: VPCs, subnets, route tables (including the main table), internet gateways, security groups (including group-to-group references), EC2 instances (IMDS settings, instance profiles), EBS volumes, S3 bucket public-access status and Block Public Access settings.
- Findings: eight rules with remediation guidance and a rule catalog (`infralens rules`), including topology-aware internet-exposure analysis. See [rules.md](rules.md).
- Policy: disabled rules, severity overrides, and expiring waivers ([policy.md](policy.md)).
- Reporting: table, JSON, SARIF 2.1.0 and Markdown output.
- Storage: SQLite via `internal/storage.Store`.
- Export: JSON, CSV, DOT.
- Unit tests for `resource`, `graph`, `diff`, `findings`, `policy`, `report`, `awsdiscovery` orchestration, `normalize`, `export`, `config` (no AWS credentials or database required).

Not yet done, and required before Phase 1 can be considered verified: run `go mod tidy && go build ./... && go vet ./... && go test ./...` in a Go 1.23+ environment. This repository was authored without a local Go toolchain, so that step has not happened yet.

## Phase 2 — Discovery breadth

- Additional services: RDS, IAM (users/roles/policies with wildcard or public trust), Lambda, ELB/ALB/NLB, ECS/EKS control-plane metadata.
- Completed: multi-region scan in a single `scan` invocation (`--regions a,b,c`). Not yet done: `--all-regions`, which needs `ec2:DescribeRegions` and opt-in region handling.
- ACL-based (not just policy-based) S3 public-access detection.
- Additional findings rules as discovery breadth grows (e.g. public RDS instances, overly permissive IAM trust policies; unencrypted EBS volumes are already covered).

## Phase 3 — Operational hardening

- Completed: `--concurrency` for parallel per-region/per-service discovery.
- Completed: retry with exponential backoff and jitter around AWS API throttling (`--max-attempts`).
- Completed: partial-scan recovery. A scan where some regions or services failed is persisted with status `partial` and whatever the rest discovered, instead of being discarded (`--allow-partial` accepts it in CI).
- Completed: SARIF and Markdown output, policy files with expiring waivers, and an example GitHub Actions workflow.
- Not yet done: rate limiting across services (each task is bounded, but the total request rate is not), and per-task timeouts.
- Completed: `infralens findings --fail-on high` (or similar) as a first-class CI gate, instead of requiring a `jq` pipeline.
- Completed: structured logging (`--log-level`, also configurable via `INFRALENS_LOG_LEVEL`) wired through discovery and storage-facing commands.

## Phase 4 — Storage flexibility

- PostgreSQL implementation of `storage.Store`, for teams that want centralized scan history instead of per-machine SQLite files.
- `infralens scan --store postgres://...` (or config-file-driven backend selection).

## Phase 5 — Optional local viewer

- `infralens serve`: a local, read-only HTTP server over stored scans (graph + findings views), built only after the CLI commands it would visualize are stable. This is explicitly an extension point, not the product — no work happens here until Phases 1–3 are solid.
- If built, it replaces the deprecated `frontend/` React shell rather than reviving it; any new UI is served directly by the Go binary, not a separate npm project.

## Explicitly Out of Scope

- Hosted/multi-tenant SaaS deployment.
- Cloud providers other than AWS.
- A browser extension.
- Anything not related to AWS discovery, graphing, findings, or scan diffing (per project constraints).
