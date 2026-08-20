# Roadmap

## Phase 1 — CLI foundation (this repository, current state)

- Go module, package layout, and command surface (`scan`, `graph`, `findings`, `diff`, `export`, `scans`, `serve` stub) as described in [architecture.md](architecture.md) and [cli.md](cli.md).
- Discovery: VPCs, subnets, route tables, internet gateways, security groups, EC2 instances, S3 bucket public-access status.
- Findings: open security groups, public S3 buckets, internet-exposed instances.
- Storage: SQLite via `internal/storage.Store`.
- Export: JSON, CSV, DOT.
- Unit tests for `resource`, `graph`, `diff`, `findings`, `normalize`, `export`, `config` (no AWS credentials or database required).

Not yet done, and required before Phase 1 can be considered verified: run `go mod tidy && go build ./... && go vet ./... && go test ./...` in a Go 1.23+ environment. This repository was authored without a local Go toolchain, so that step has not happened yet.

## Phase 2 — Discovery breadth

- Additional services: RDS, IAM (users/roles/policies with wildcard or public trust), Lambda, ELB/ALB/NLB, ECS/EKS control-plane metadata.
- Multi-region scan in a single `scan` invocation (`--region` repeated or `--all-regions`).
- ACL-based (not just policy-based) S3 public-access detection.
- Additional findings rules as discovery breadth grows (e.g. public RDS instances, overly permissive IAM trust policies, unencrypted volumes).

## Phase 3 — Operational hardening

- `--concurrency` for parallel per-region/per-service discovery.
- Retry/backoff around AWS API throttling.
- Partial-scan recovery: persist a `failed` scan with whatever was discovered before the error, instead of discarding it.
- `infralens findings --fail-on high` (or similar) as a first-class CI gate, instead of requiring a `jq` pipeline.
- Structured logging (`--log-level`, already resolved by `internal/config`) wired through discovery and storage.

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
