# Security Notes

InfraLens is designed to analyze AWS infrastructure using least-privilege, read-only access, and to store the results locally under the user's control.

## Rules

- Never commit AWS access keys, session tokens, Terraform state, or a populated `infralens.db`.
- Prefer IAM role assumption (`--profile` pointing at an assumed-role profile) or standard AWS SDK credential resolution over long-lived static keys.
- Limit discovery permissions to the read-only actions InfraLens actually calls (see below). `infralens` never calls a mutating AWS API.
- Treat account metadata and discovered infrastructure as sensitive operational data: exported JSON/CSV/DOT files can reveal topology, security group rules, and public-exposure findings, and should be handled like any other infrastructure secret.
- Findings and exported scans are not sanitized by default; avoid pasting raw scan output into public issue trackers or chat.

## Required Read-Only Permissions

The `scan` command currently calls:

```text
ec2:DescribeVpcs
ec2:DescribeSubnets
ec2:DescribeRouteTables
ec2:DescribeInternetGateways
ec2:DescribeSecurityGroups
ec2:DescribeInstances
s3:ListAllMyBuckets
s3:GetBucketPolicyStatus
sts:GetCallerIdentity
```

`terraform/` holds (or will hold, per the roadmap) an IAM role module scoped to exactly this permission set, for accounts that want to grant InfraLens a dedicated read-only role rather than reusing an operator's credentials.

## Local Data

- Scan history lives in a local SQLite file (default `infralens.db`, configurable via `--db` or `INFRALENS_DB_PATH`). It is not encrypted at rest by InfraLens; rely on filesystem/disk encryption if that's required in your environment.
- `.env.example` documents optional local configuration; it never contains secrets, and `.env*` is gitignored.
- No telemetry, network calls, or external services are used beyond the AWS APIs InfraLens is explicitly pointed at.

## Planned Controls

- `terraform/` will ship a minimal read-only IAM role/policy matching the permission list above.
- CI usage (`infralens scan` + `infralens findings --severity high` as a pipeline gate) should run under a dedicated read-only role, not a developer's personal credentials.
