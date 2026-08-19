# Security Notes

InfraLens is intended to analyze AWS infrastructure using least-privilege, read-only access.

## Rules

- Never commit AWS access keys, session tokens, or Terraform state.
- Prefer IAM role assumption and standard AWS SDK credential resolution.
- Limit discovery permissions to read-only actions required for supported services.
- Treat account metadata and discovered infrastructure as sensitive operational data.
- Avoid logging raw credentials or full discovery payloads unless explicitly sanitized.

## Planned Controls

- `.env.example` documents local configuration without secrets.
- Terraform state remains untracked.
- Future phases will document exact IAM permissions for the read-only role.
- API endpoints that expose discovery results will be designed for authenticated use.

