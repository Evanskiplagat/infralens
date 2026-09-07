# InfraLens

InfraLens is a Go command-line tool for discovering AWS resources, mapping their relationships, reporting possible exposure risks, and comparing infrastructure scans over time.

It runs locally with read-only AWS credentials and stores scan data in SQLite. Output is available in formats suitable for terminal use, scripts, CI/CD pipelines, and graph visualisation.

## Why a CLI

The CLI runs within the caller's AWS credential scope and does not require a hosted service. Its structured output can be passed to tools such as `jq`, used in a CI check, or compared between scans.

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
