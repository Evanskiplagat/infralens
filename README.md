# InfraLens

InfraLens is a CLI-first tool for AWS infrastructure discovery, relationship graphing, exposure findings, and scan-to-scan diffing. It runs as a single Go binary: point it at read-only AWS credentials, and it turns a fragmented account into a queryable graph of resources, relationships, and risk.

InfraLens is not a hosted web app or browser extension. It's built to run on a laptop, in CI/CD, or on a cron job — with structured output designed for scripting and automation first, human-readable tables second.

## Why a CLI

Infrastructure discovery is naturally a batch, credential-scoped, automatable operation — the kind of thing that belongs in a pipeline step or a terminal, not a hosted service with its own auth and uptime. A CLI keeps the trust boundary small (it runs with the credentials you already have, produces a local file, and does nothing else), and it composes: pipe `export --format json` into `jq`, wire `findings` into a CI gate, or diff two scans in a pull request check.

## Target Capabilities

```text
infralens scan      Discover AWS resources using read-only credentials
infralens graph      Build and inspect resource relationships
infralens findings   Detect likely public exposure and risky topology
infralens diff       Compare two scans over time
infralens export     Emit JSON, CSV, or Graphviz/DOT
infralens scans      List stored scans
infralens serve      (planned) local read-only viewer — see docs/roadmap.md
```

See [docs/cli.md](docs/cli.md) for full command usage and examples.

## Repository Layout

```text
cmd/infralens/     CLI entrypoint (main.go)
internal/
  cli/             Command parsing and wiring
  config/          Config resolution (file, env, flags)
  awsdiscovery/    Read-only AWS SDK calls, isolated from the rest of the codebase
  normalize/       Raw AWS shapes -> internal resource/edge model
  graph/           In-memory relationship graph and traversal
  findings/        Exposure and topology rule engine
  storage/         Store interface + SQLite implementation
  export/          JSON, CSV, and DOT serializers
  diff/             Scan comparison logic
  resource/        Shared domain types (Resource, Edge, Scan)
docs/              Architecture, CLI spec, security notes, roadmap
frontend/          Deprecated React shell; not part of the product (see frontend/README.md)
terraform/         Read-only discovery IAM role module
demo/              Fixtures and sample scan data
```

## Quick Start

Requires Go 1.23+ and read-only AWS credentials (a named profile or the standard SDK credential chain).

```bash
go build -o bin/infralens ./cmd/infralens

./bin/infralens scan --profile my-readonly-profile --region us-east-1
./bin/infralens findings --severity high
./bin/infralens graph --format dot --out graph.dot
./bin/infralens diff --from <scan-id> --to latest
```

Scan history is stored locally in a SQLite file (`infralens.db` by default; override with `--db` or `INFRALENS_DB_PATH`).

## Status

The Go module, package layout, and command surface described here are implemented in this repository. This development environment does not have a Go toolchain installed, so the code has not been compiled or tested here — before relying on it, run:

```bash
go mod tidy
go build ./...
go vet ./...
go test ./...
```

See [docs/roadmap.md](docs/roadmap.md) for what's implemented versus planned.

## Security

InfraLens is designed to run with least-privilege, read-only AWS credentials. See [docs/security.md](docs/security.md).
