# Policy Files

A policy lets a team tune what InfraLens reports without forking its rules. It can disable rules that do not apply, change a rule's severity to match your risk appetite, and waive individual findings with a written reason and an expiry date, so an exception cannot quietly become permanent.

Policies are applied when findings are *reported* (`infralens findings --policy FILE`), not when a scan runs. Stored scans always keep the full, unfiltered findings, so the same scan can be evaluated under different policies and nothing is lost if a waiver is later removed.

## Format

A policy is a JSON document. A complete example lives in [examples/infralens.policy.json](../examples/infralens.policy.json).

```json
{
  "version": 1,
  "disabled_rules": ["unused_security_group"],
  "severity_overrides": {
    "default_vpc_in_use": "info"
  },
  "suppressions": [
    {
      "rule_id": "public_s3_bucket",
      "resource": "s3_bucket/marketing-site-*",
      "reason": "Public static website; content reviewed by the security team",
      "owner": "platform-team",
      "expires": "2027-03-31"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `version` | Required. Must be `1`. |
| `disabled_rules` | Rule IDs to drop entirely. Exact IDs only; see [rules.md](rules.md). |
| `severity_overrides` | Map of rule ID to `info`, `low`, `medium`, `high` or `critical`. Applies to every finding from that rule. |
| `suppressions[].rule_id` | Rule the waiver covers. `*` wildcards are allowed. |
| `suppressions[].resource` | Resource ID pattern, such as `s3_bucket/site-*`. `*` matches any run of characters, including `/`. Use `*` alone to match every resource. |
| `suppressions[].reason` | Required. Why the finding is acceptable. It is carried into SARIF output as the suppression justification. |
| `suppressions[].owner` | Optional. Who is accountable for the exception. |
| `suppressions[].expires` | Optional last day the waiver applies, as `YYYY-MM-DD` in UTC. The waiver holds for that whole day. |

## Validation is strict on purpose

A policy that silently does nothing is worse than no policy, so InfraLens rejects a file instead of guessing:

- Unknown fields are errors, so a typo such as `supressions` fails loudly.
- Rule IDs in `disabled_rules` and `severity_overrides` must name a built-in rule, so a typo cannot leave a rule enabled by accident.
- Every problem is reported at once, with the offending entry's position, so a file can be fixed in one pass.

## How a policy is applied

For each finding, in order:

1. If its rule is in `disabled_rules`, it is dropped.
2. If its rule has a severity override, the new severity replaces the old one.
3. If a non-expired waiver matches its rule and resource, it is suppressed. The first matching waiver wins.

Overrides run before waivers and before `--severity` and `--fail-on`, so `--fail-on high` respects a rule you have downgraded.

When combined with `--baseline`, the policy is applied to **both** scans before they are compared. That way a waiver or override is judged the same way on each side and does not show up as a spurious new finding.

## Waivers that need attention

`infralens findings` warns on stderr about two situations:

- **Expired waivers.** After its `expires` date a waiver stops suppressing anything, and the findings it covered are reported again. The warning names the waiver so it can be renewed deliberately or removed.
- **Unmatched waivers.** A waiver that matches no current finding usually means the issue was fixed. Remove it so it cannot later mask a different problem on the same resource.

Suppressed findings are left out of `json` output and only counted in `table` and `markdown` output, but they are included in `sarif` output with a SARIF `suppressions` entry holding the reason, so code-scanning dashboards keep an audit trail.

## Reviewing a policy in CI

Treat the policy file like code: require review for changes, and give every waiver an `owner` and an `expires` date. A short expiry (a quarter or less) forces a periodic decision instead of an open-ended exception.
