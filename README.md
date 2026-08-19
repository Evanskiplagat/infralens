# InfraLens

InfraLens is an AWS infrastructure discovery and visualization tool built to map relationships between cloud resources across an AWS account.

The project is being built in small, runnable phases. The end state is intended to support:

- AWS account discovery using read-only permissions
- Resource normalization into an internal graph model
- Relationship analysis across networking, compute, and data services
- Interactive graph visualization in a web UI
- Historical scan storage and change tracking

## Current Phase

Phase 1 establishes the public repository baseline:

- project documentation
- backend directory scaffolding
- runnable React + TypeScript frontend shell
- frontend smoke tests

## Repository Layout

```text
backend/      Go service, discovery engine, API, storage
frontend/     React application for graph and findings UI
docs/         Architecture and security decisions
terraform/    IaC for read-only role and demo environments
demo/         Fixtures and sample scan data
```

## Prerequisites

- Node.js 24+
- npm 11+
- Go 1.23+ for backend work in later phases
- Docker Desktop for database and local stack phases

## Quick Start

```bash
cd frontend
npm install
npm run dev
```

Then open the local Vite URL printed in the terminal.

## Phase Notes

Go and Docker are not available in the current machine environment used for this phase, so backend and container execution are intentionally deferred until the toolchain is present. The repository still remains runnable through the frontend shell and its tests.

