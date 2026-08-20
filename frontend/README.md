# Frontend (Deprecated)

This React + TypeScript shell was built during an earlier phase when InfraLens was envisioned as a web app. The product direction has since changed: InfraLens is a CLI (see the repository root [README.md](../README.md)), and this directory is not part of it.

This code is kept only as a reference for a possible future optional local viewer (`infralens serve`, see [docs/roadmap.md](../docs/roadmap.md#phase-5--optional-local-viewer)), which — if built — would be served directly by the Go binary rather than run as a standalone npm project like this one. Until then:

- This directory is not built, tested, or shipped as part of InfraLens.
- Do not add new features here; the CLI is the product surface.
- It may be deleted entirely in a future cleanup if Phase 5 takes a different shape.
