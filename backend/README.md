# Backend

The Go backend will own:

- AWS discovery
- resource normalization
- graph construction
- findings generation
- REST API
- PostgreSQL persistence

Planned package layout:

```text
cmd/server
internal/api
internal/aws
internal/config
internal/discovery
internal/findings
internal/graph
internal/scans
internal/storage
```

Go source files are intentionally not added in this phase because the current environment does not have the Go toolchain installed, so they cannot be truthfully verified as runnable yet.

