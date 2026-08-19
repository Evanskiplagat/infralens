# Architecture Overview

InfraLens is being designed as a single deployable web application with a Go backend and React frontend.

## Principles

- AWS discovery stays isolated from graph construction.
- Raw AWS SDK shapes do not leak through the rest of the codebase.
- Infrastructure data is normalized into an internal resource model before graph analysis.
- Storage is relational because scans, resources, edges, and diffs are strongly structured.
- The first implementation target is one backend service, not microservices.

## Planned Flow

1. The backend authenticates to AWS through standard SDK credential resolution or an assumed read-only role.
2. Service-specific discovery packages collect raw AWS data.
3. Discovery results are mapped into normalized resource and relationship types.
4. The graph layer calculates edges and flags likely public exposure.
5. The API serves scan summaries, graph payloads, and findings to the frontend.
6. PostgreSQL stores scans so future phases can compare drift over time.

## Early Trade-Offs

- Start with a monolith because discovery, graph logic, and API evolve together.
- Start with REST because scan, resource, and graph payloads are simple to expose and test.
- Delay Terraform-heavy local infrastructure until the core domain model and API contract exist.

