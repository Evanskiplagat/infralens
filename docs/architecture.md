# Architecture

InfraLens is a single Go CLI binary, not a client/server web application. There is no frontend to serve and no API to version; every command runs a self-contained pipeline against local state and AWS APIs.

## Principles

- CLI-first: every capability is a command with structured (JSON) and human-readable output. Anything else — a TUI, a local web viewer — is an optional layer on top of the same commands, not a separate product.
- Raw AWS SDK shapes never leave the `awsdiscovery` package. Everything downstream (`normalize`, `graph`, `findings`, `storage`, `export`) works only with InfraLens's own `resource.Resource` / `resource.Edge` types.
- Discovery, normalization, graph construction, and findings evaluation are separate packages with one-directional dependencies, so each is independently testable without AWS credentials or a database.
- Storage is accessed through a `Store` interface (`internal/storage`), not a concrete SQLite type, so a PostgreSQL implementation can be added later without touching the CLI or domain packages.
- Start with a monolith and a stdlib-only CLI. The only external dependencies are the AWS SDK (required for discovery) and a pure-Go SQLite driver (required for persistence without a cgo toolchain) — no web framework, no ORM, no CLI framework.

## Package Boundaries

```text
cmd/infralens        entrypoint; delegates immediately to internal/cli
internal/cli         flag parsing, command dispatch, output formatting
internal/config      merges defaults, config file, env vars, and flags
internal/resource     shared domain types: Resource, Edge, Scan
internal/awsdiscovery AWS SDK calls (read-only), Discoverer interface, raw types
internal/normalize    raw awsdiscovery.Snapshot -> []resource.Resource, []resource.Edge
internal/graph        adjacency index over resources/edges + traversal
internal/findings     Rule interface, rule catalog, built-in rules, internet-path analysis
internal/policy       Policy files: disabled rules, severity overrides, expiring waivers
internal/report       SARIF 2.1.0 and Markdown renderers
internal/storage       Store interface
internal/storage/sqlite SQLite implementation of Store
internal/export        JSON, CSV, DOT serializers
internal/diff           resource/edge set comparison between two scans
```

Dependency direction is strictly downstream: `cli` depends on everything; `resource` depends on nothing. `awsdiscovery` has no dependency on `resource` — it only produces plain Go structs — so `normalize` is the single seam where AWS's data model becomes InfraLens's data model.

## Scan Pipeline

```mermaid
flowchart LR
    A[awsdiscovery] -->|Snapshot| B[normalize]
    B -->|Resources + Edges| C[graph.Build]
    C --> D[findings.Run]
    B --> E[(storage.Store)]
    D --> E
    C --> E
```

1. `infralens scan` resolves AWS credentials via the standard SDK chain (profile, environment, assumed role, or instance role) and calls read-only discovery APIs for each supported service.
2. `normalize` maps raw API responses into `resource.Resource` and `resource.Edge` values, including structural edges (VPC contains Subnet, Instance is member-of SecurityGroup, RouteTable routes-to Subnet, VPC attached-to InternetGateway).
3. `graph.Build` indexes resources and edges for traversal.
4. `findings.Run` evaluates every built-in rule against the graph and produces `Finding` records, ordered most severe first so output is stable. See [rules.md](rules.md).
5. `storage.Store` persists the scan, its resources, edges, and findings to SQLite, keyed by a scan ID.
6. `graph`, `findings`, `diff`, and `export` commands operate on stored scans after the fact — they don't require AWS credentials or network access, only the local database.

## Discovery orchestration

`awsdiscovery.Collect` expands the enabled discoverers and the requested regions into a plan of independent tasks: one per (discoverer, region), except that account-wide services such as S3 (which implement the `Global` interface) appear once. Tasks run with bounded concurrency and each fills its own `Snapshot`, so retries never duplicate data and there is no shared mutable state. Failed attempts are retried with exponential backoff and jitter when the error looks like throttling or a transient fault (matched through the `ErrorCode()` method AWS SDK errors implement, so this package needs no SDK error types). After all tasks finish, snapshots are merged in plan order, which makes a scan independent of scheduling.

A task that ultimately fails is recorded as a `Failure` while the rest carry on. The CLI stores the outcome as `complete`, `partial` (some tasks failed) or `failed` (none succeeded). Optional data that a role may not be permitted to read (EBS volumes) is skipped with a warning rather than failing its whole region.

## Findings analysis

Rules are pure functions over the graph, so they need no AWS access. Two ideas keep them honest:

- **Topology, not just attributes.** `findings.InternetPathFor` walks `subnet -contains-> instance`, `route table -routes_to-> subnet` (or the VPC's main route table when a subnet has no explicit association) and `vpc -attached_to-> internet gateway`. The result is one of *internet route*, *no internet route*, or *unknown*, and rules use it to raise or lower severity and to print the evidence.
- **Unknown is not safe.** Discovery is best-effort. Attributes that could not be determined (IMDS setting, S3 Block Public Access) are left absent rather than defaulted, and rules skip them instead of guessing. Missing route data keeps a finding at its base severity.

`RuleInfo` (title, description, remediation, references, tags) lives with each rule rather than on each `Finding`, so stored scans stay small and guidance can improve without rewriting history. `docs/rules.md` is checked against the catalog by a test, so the two cannot drift.

## Policy and reporting

`policy` and `report` sit at the edge of the pipeline and operate only on stored findings. A policy is applied when findings are reported, never when a scan is stored, so the same scan can be evaluated under different policies and no information is lost. `report` renders SARIF and Markdown from findings plus the rule catalog, with no dependency on storage or AWS.

## Storage

SQLite is the default and only implementation today, chosen because InfraLens's data — scans, resources, edges, findings — is strongly structured and a single local file matches the tool's "runs on your laptop or in CI" model with zero setup. The pure-Go `modernc.org/sqlite` driver is used specifically to avoid a cgo build requirement, keeping `go build` sufficient to produce a portable binary.

`internal/storage.Store` is the seam for a future PostgreSQL backend (e.g. for teams centralizing scan history): any implementation satisfying the interface can be swapped in via `internal/cli` without changes to discovery, graph, or findings code.

## The Frontend

The `frontend/` directory contains a React shell from an earlier phase where the product was envisioned as a web app. That framing has been replaced by the CLI described here. The directory is kept only as deprecated, optional tooling — see `frontend/README.md` — and is not built, tested, or shipped as part of InfraLens. A local web viewer may return later as a thin layer over `infralens serve` (see roadmap), but only once the CLI itself is complete.
