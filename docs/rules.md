# Built-in Rules

Every rule reports findings against a resource in a stored scan. Rule IDs are stable across releases, so policies, dashboards and CI filters can depend on them. `infralens rules` prints the same catalog, and `infralens rules --id <rule>` prints the full detail for one rule.

| Rule | Default severity | What it detects |
| --- | --- | --- |
| `default_vpc_in_use` | low | Workloads run in the default VPC |
| `imdsv1_enabled` | medium | EC2 instance allows IMDSv1 |
| `internet_exposed_instance` | high | EC2 instance is reachable from the internet |
| `open_security_group` | medium | Security group allows unrestricted ingress |
| `public_s3_bucket` | high | S3 bucket is publicly accessible |
| `s3_public_access_block_disabled` | medium | S3 Block Public Access is not fully enabled |
| `unencrypted_ebs_volume` | medium | EBS volume is not encrypted |
| `unused_security_group` | info | Security group is not attached to any scanned resource |

Severity is context-sensitive: a rule may raise or lower it for an individual finding, as described below.

## `default_vpc_in_use`

The default VPC ships with public subnets that auto-assign public IP addresses and a permissive default security group, so anything launched there is one mistake away from internet exposure.

**Remediation.** Create a purpose-built VPC with private subnets, migrate the workloads, and delete the default VPC once it is empty.

- https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html

## `imdsv1_enabled`

The instance metadata service accepts unauthenticated IMDSv1 requests. A server-side request forgery bug in any application on the instance can then be used to steal the credentials of its IAM role. The finding is high when the instance also has an instance profile and a public IP address.

**Remediation.** Require IMDSv2 by setting HttpTokens to required (aws ec2 modify-instance-metadata-options --http-tokens required), and enforce it for new instances in launch templates.

- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html

## `internet_exposed_instance`

The instance has a public IP address and belongs to a security group that admits traffic from anywhere. The route from the internet is traced through the instance's subnet, route table and internet gateway: a confirmed route to an internet gateway raises severity (critical when all traffic or a sensitive port is open), while a subnet known to have no internet route lowers it to medium.

**Remediation.** Remove the public IP or move the instance to a private subnet behind a load balancer or NAT gateway, and narrow the security group so only required sources can connect.

- https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html
- https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

## `open_security_group`

A security group rule admits inbound traffic from anywhere on the internet (0.0.0.0/0 or ::/0). Rules that expose all traffic are critical; rules covering administrative or database ports such as SSH, RDP, MySQL, PostgreSQL, Redis, Elasticsearch or MongoDB are high; anything else is medium.

**Remediation.** Restrict the rule's source to the specific CIDR ranges or security groups that need access, and put administrative access behind a VPN or AWS Systems Manager Session Manager.

- https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

## `public_s3_bucket`

S3's own policy evaluation reports the bucket policy as public, so anyone on the internet may be able to read or list its contents.

**Remediation.** Remove the public statements from the bucket policy, or turn on S3 Block Public Access for the bucket. Serve intentionally public content through CloudFront instead.

- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html

## `s3_public_access_block_disabled`

The bucket does not have all four Block Public Access settings turned on, so a future ACL or policy change could make it public without any guardrail stopping it.

**Remediation.** Enable all four Block Public Access settings on the bucket, or account-wide with aws s3control put-public-access-block.

- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html

## `unencrypted_ebs_volume`

The volume, and any snapshot taken from it, stores data unencrypted at rest.

**Remediation.** Create an encrypted copy through a snapshot and swap it in, and turn on EBS encryption by default for the region so new volumes are encrypted automatically.

- https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html

## `unused_security_group`

No EC2 instance in the scan is a member of the group and no other group's rules reference it. InfraLens does not yet discover every service that can use a security group (RDS, load balancers, Lambda), so treat this as a cleanup hint, not proof.

**Remediation.** Confirm the group is unused in the console, then delete it to shrink the attack surface.

- https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
