package findings

import (
	"fmt"
	"sort"
	"strings"

	"infralens/internal/graph"
	"infralens/internal/resource"
)

// Rule IDs, stable across releases so automation can filter on them.
const (
	RuleOpenSecurityGroup   = "open_security_group"
	RulePublicS3Bucket      = "public_s3_bucket"
	RuleExposedInstance     = "internet_exposed_instance"
	RuleIMDSv1Enabled       = "imdsv1_enabled"
	RuleUnencryptedVolume   = "unencrypted_ebs_volume"
	RuleUnusedSecurityGroup = "unused_security_group"
	RuleDefaultVPCInUse     = "default_vpc_in_use"
	RuleS3PublicAccessBlock = "s3_public_access_block_disabled"
)

// sensitivePorts are flagged as High severity when open to the world;
// any other unrestricted ingress is still reported, at Medium severity.
var sensitivePorts = []int32{22, 3389, 3306, 5432, 6379, 9200, 27017}

func isOpenCIDR(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

// isAllTraffic reports whether a rule admits every protocol or every port.
func isAllTraffic(rule resource.SGRule) bool {
	if rule.Protocol == "-1" {
		return true
	}
	return rule.FromPort <= 0 && rule.ToPort >= 65535
}

// coversSensitivePort reports whether a TCP-capable rule's port range
// includes a commonly attacked service port (SSH, RDP, databases, ...),
// including when the range is broad enough to cover it by accident.
func coversSensitivePort(rule resource.SGRule) bool {
	switch rule.Protocol {
	case "-1":
		return true
	case "tcp", "6":
	default:
		return false
	}
	for _, p := range sensitivePorts {
		if rule.FromPort <= p && p <= rule.ToPort {
			return true
		}
	}
	return false
}

func describeRule(rule resource.SGRule) string {
	if rule.Protocol == "-1" {
		return "all traffic"
	}
	if rule.FromPort == rule.ToPort {
		return fmt.Sprintf("%s/%d", rule.Protocol, rule.FromPort)
	}
	return fmt.Sprintf("%s/%d-%d", rule.Protocol, rule.FromPort, rule.ToPort)
}

// activeInstance reports whether an instance still exists as far as AWS
// traffic is concerned; terminated instances linger in API results for a
// while and would only produce noise.
func activeInstance(r resource.Resource) bool {
	state, _ := r.Attributes[resource.AttrState].(string)
	return state != "terminated" && state != "shutting-down"
}

func boolAttr(r resource.Resource, key string) (value, present bool) {
	v, ok := r.Attributes[key].(bool)
	return v, ok
}

func stringAttr(r resource.Resource, key string) string {
	s, _ := r.Attributes[key].(string)
	return s
}

// sortedResources returns resources of one kind in a stable order so rules
// emit findings deterministically regardless of map iteration.
func sortedResources(g *graph.Graph, kind resource.Kind) []resource.Resource {
	var out []resource.Resource
	for _, r := range g.Resources {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---------------------------------------------------------------------------

type openSecurityGroupRule struct{}

func (openSecurityGroupRule) ID() string { return RuleOpenSecurityGroup }

func (openSecurityGroupRule) Info() RuleInfo {
	return RuleInfo{
		ID:    RuleOpenSecurityGroup,
		Title: "Security group allows unrestricted ingress",
		Description: "A security group rule admits inbound traffic from anywhere on the internet " +
			"(0.0.0.0/0 or ::/0). Rules that expose all traffic are critical; rules covering " +
			"administrative or database ports such as SSH, RDP, MySQL, PostgreSQL, Redis, " +
			"Elasticsearch or MongoDB are high; anything else is medium.",
		Remediation: "Restrict the rule's source to the specific CIDR ranges or security groups that " +
			"need access, and put administrative access behind a VPN or AWS Systems Manager Session Manager.",
		DefaultSeverity: SeverityMedium,
		References:      []string{"https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"},
		Tags:            []string{"network", "exposure"},
	}
}

func (openSecurityGroupRule) Evaluate(g *graph.Graph) []Finding {
	var out []Finding
	for _, r := range sortedResources(g, resource.KindSecurityGroup) {
		for _, rule := range resource.IngressRules(r.Attributes) {
			if !isOpenCIDR(rule.CIDR) {
				continue
			}
			severity := SeverityMedium
			switch {
			case isAllTraffic(rule):
				severity = SeverityCritical
			case coversSensitivePort(rule):
				severity = SeverityHigh
			}
			out = append(out, Finding{
				RuleID:     RuleOpenSecurityGroup,
				ResourceID: r.ID,
				Severity:   severity,
				Title:      fmt.Sprintf("Security group %s allows unrestricted ingress", r.Name),
				Description: fmt.Sprintf(
					"%s permits inbound %s from %s.", r.Name, describeRule(rule), rule.CIDR,
				),
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------

type publicS3BucketRule struct{}

func (publicS3BucketRule) ID() string { return RulePublicS3Bucket }

func (publicS3BucketRule) Info() RuleInfo {
	return RuleInfo{
		ID:    RulePublicS3Bucket,
		Title: "S3 bucket is publicly accessible",
		Description: "S3's own policy evaluation reports the bucket policy as public, so anyone on " +
			"the internet may be able to read or list its contents.",
		Remediation: "Remove the public statements from the bucket policy, or turn on S3 Block Public " +
			"Access for the bucket. Serve intentionally public content through CloudFront instead.",
		DefaultSeverity: SeverityHigh,
		References:      []string{"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"},
		Tags:            []string{"storage", "exposure"},
	}
}

func (publicS3BucketRule) Evaluate(g *graph.Graph) []Finding {
	var out []Finding
	for _, r := range sortedResources(g, resource.KindS3Bucket) {
		if public, _ := boolAttr(r, resource.AttrBucketPublic); public {
			out = append(out, Finding{
				RuleID:      RulePublicS3Bucket,
				ResourceID:  r.ID,
				Severity:    SeverityHigh,
				Title:       fmt.Sprintf("S3 bucket %s is publicly accessible", r.Name),
				Description: fmt.Sprintf("Bucket policy evaluation reports %s as public.", r.Name),
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------

type exposedInstanceRule struct{}

func (exposedInstanceRule) ID() string { return RuleExposedInstance }

func (exposedInstanceRule) Info() RuleInfo {
	return RuleInfo{
		ID:    RuleExposedInstance,
		Title: "EC2 instance is reachable from the internet",
		Description: "The instance has a public IP address and belongs to a security group that " +
			"admits traffic from anywhere. The route from the internet is traced through the " +
			"instance's subnet, route table and internet gateway: a confirmed route to an internet " +
			"gateway raises severity (critical when all traffic or a sensitive port is open), while " +
			"a subnet known to have no internet route lowers it to medium.",
		Remediation: "Remove the public IP or move the instance to a private subnet behind a load balancer " +
			"or NAT gateway, and narrow the security group so only required sources can connect.",
		DefaultSeverity: SeverityHigh,
		References: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html",
			"https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
		},
		Tags: []string{"network", "exposure", "attack-path"},
	}
}

type openIngress struct {
	group string
	rule  resource.SGRule
}

func (exposedInstanceRule) Evaluate(g *graph.Graph) []Finding {
	var out []Finding
	for _, r := range sortedResources(g, resource.KindEC2Instance) {
		if !activeInstance(r) {
			continue
		}
		if hasPublicIP, _ := boolAttr(r, resource.AttrHasPublicIP); !hasPublicIP {
			continue
		}
		open := openIngressFor(g, r.ID)
		if len(open) == 0 {
			continue
		}

		path := InternetPathFor(g, r.ID)
		severity := SeverityHigh
		switch path.State {
		case RouteInternet:
			for _, o := range open {
				if isAllTraffic(o.rule) || coversSensitivePort(o.rule) {
					severity = SeverityCritical
					break
				}
			}
		case RouteNone:
			severity = SeverityMedium
		}

		out = append(out, Finding{
			RuleID:     RuleExposedInstance,
			ResourceID: r.ID,
			Severity:   severity,
			Title:      fmt.Sprintf("Instance %s is reachable from the internet", r.Name),
			Description: fmt.Sprintf(
				"%s has a public IP and belongs to a security group with unrestricted ingress (%s). Route evidence: %s.",
				r.Name, summarizeOpen(open), path.Describe(displayName(r)),
			),
		})
	}
	return out
}

// openIngressFor lists the world-open ingress rules of every security group
// the instance belongs to, ordered by group then rule for stable output.
func openIngressFor(g *graph.Graph, instanceID string) []openIngress {
	var open []openIngress
	for _, e := range g.Out(instanceID) {
		if e.Type != resource.RelMemberOf {
			continue
		}
		sg, ok := g.Resources[e.To]
		if !ok || sg.Kind != resource.KindSecurityGroup {
			continue
		}
		for _, rule := range resource.IngressRules(sg.Attributes) {
			if isOpenCIDR(rule.CIDR) {
				open = append(open, openIngress{group: displayName(sg), rule: rule})
			}
		}
	}
	sort.SliceStable(open, func(i, j int) bool { return open[i].group < open[j].group })
	return open
}

func summarizeOpen(open []openIngress) string {
	const maxShown = 3
	parts := make([]string, 0, maxShown+1)
	for i, o := range open {
		if i == maxShown {
			parts = append(parts, fmt.Sprintf("and %d more", len(open)-maxShown))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s from %s", o.group, describeRule(o.rule), o.rule.CIDR))
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------

type imdsv1Rule struct{}

func (imdsv1Rule) ID() string { return RuleIMDSv1Enabled }

func (imdsv1Rule) Info() RuleInfo {
	return RuleInfo{
		ID:    RuleIMDSv1Enabled,
		Title: "EC2 instance allows IMDSv1",
		Description: "The instance metadata service accepts unauthenticated IMDSv1 requests. A " +
			"server-side request forgery bug in any application on the instance can then be used " +
			"to steal the credentials of its IAM role. The finding is high when the instance also " +
			"has an instance profile and a public IP address.",
		Remediation: "Require IMDSv2 by setting HttpTokens to required " +
			"(aws ec2 modify-instance-metadata-options --http-tokens required), and enforce it for " +
			"new instances in launch templates.",
		DefaultSeverity: SeverityMedium,
		References:      []string{"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"},
		Tags:            []string{"compute", "credentials"},
	}
}

func (imdsv1Rule) Evaluate(g *graph.Graph) []Finding {
	var out []Finding
	for _, r := range sortedResources(g, resource.KindEC2Instance) {
		if !activeInstance(r) {
			continue
		}
		required, known := boolAttr(r, resource.AttrIMDSv2Required)
		if !known || required {
			continue
		}
		severity := SeverityMedium
		detail := "IMDSv1 is enabled."
		profile := stringAttr(r, resource.AttrIAMInstanceProfile)
		if hasPublicIP, _ := boolAttr(r, resource.AttrHasPublicIP); profile != "" && hasPublicIP {
			severity = SeverityHigh
			detail = "IMDSv1 is enabled on an internet-facing instance that has an IAM instance profile, " +
				"so a request-forgery bug could expose the role's credentials."
		}
		out = append(out, Finding{
			RuleID:      RuleIMDSv1Enabled,
			ResourceID:  r.ID,
			Severity:    severity,
			Title:       fmt.Sprintf("Instance %s allows IMDSv1", r.Name),
			Description: fmt.Sprintf("%s %s", r.Name, detail),
		})
	}
	return out
}

// ---------------------------------------------------------------------------

type unencryptedVolumeRule struct{}

func (unencryptedVolumeRule) ID() string { return RuleUnencryptedVolume }

func (unencryptedVolumeRule) Info() RuleInfo {
	return RuleInfo{
		ID:          RuleUnencryptedVolume,
		Title:       "EBS volume is not encrypted",
		Description: "The volume, and any snapshot taken from it, stores data unencrypted at rest.",
		Remediation: "Create an encrypted copy through a snapshot and swap it in, and turn on EBS " +
			"encryption by default for the region so new volumes are encrypted automatically.",
		DefaultSeverity: SeverityMedium,
		References:      []string{"https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html"},
		Tags:            []string{"storage", "encryption"},
	}
}

func (unencryptedVolumeRule) Evaluate(g *graph.Graph) []Finding {
	var out []Finding
	for _, r := range sortedResources(g, resource.KindEBSVolume) {
		encrypted, known := boolAttr(r, resource.AttrEncrypted)
		if !known || encrypted {
			continue
		}
		detail := "It is not attached to an instance."
		var attached []string
		for _, e := range g.Out(r.ID) {
			if e.Type != resource.RelAttachedTo {
				continue
			}
			if inst, ok := g.Resources[e.To]; ok && inst.Kind == resource.KindEC2Instance {
				attached = append(attached, displayName(inst))
			}
		}
		if len(attached) > 0 {
			sort.Strings(attached)
			detail = "It is attached to " + strings.Join(attached, ", ") + "."
		}
		out = append(out, Finding{
			RuleID:      RuleUnencryptedVolume,
			ResourceID:  r.ID,
			Severity:    SeverityMedium,
			Title:       fmt.Sprintf("EBS volume %s is not encrypted", r.Name),
			Description: fmt.Sprintf("Volume %s has encryption at rest disabled. %s", r.Name, detail),
		})
	}
	return out
}

// ---------------------------------------------------------------------------

type unusedSecurityGroupRule struct{}

func (unusedSecurityGroupRule) ID() string { return RuleUnusedSecurityGroup }

func (unusedSecurityGroupRule) Info() RuleInfo {
	return RuleInfo{
		ID:    RuleUnusedSecurityGroup,
		Title: "Security group is not attached to any scanned resource",
		Description: "No EC2 instance in the scan is a member of the group and no other group's rules " +
			"reference it. InfraLens does not yet discover every service that can use a security " +
			"group (RDS, load balancers, Lambda), so treat this as a cleanup hint, not proof.",
		Remediation:     "Confirm the group is unused in the console, then delete it to shrink the attack surface.",
		DefaultSeverity: SeverityInfo,
		References:      []string{"https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"},
		Tags:            []string{"network", "hygiene"},
	}
}

func (unusedSecurityGroupRule) Evaluate(g *graph.Graph) []Finding {
	var out []Finding
	for _, r := range sortedResources(g, resource.KindSecurityGroup) {
		if stringAttr(r, resource.AttrGroupName) == "default" {
			continue // the default group cannot be deleted
		}
		used := false
		for _, e := range g.In(r.ID) {
			if e.Type == resource.RelMemberOf || e.Type == resource.RelReferences {
				used = true
				break
			}
		}
		if used {
			continue
		}
		out = append(out, Finding{
			RuleID:      RuleUnusedSecurityGroup,
			ResourceID:  r.ID,
			Severity:    SeverityInfo,
			Title:       fmt.Sprintf("Security group %s is not attached to any scanned resource", r.Name),
			Description: fmt.Sprintf("No instance uses %s and no security group rule references it.", r.Name),
		})
	}
	return out
}

// ---------------------------------------------------------------------------

type defaultVPCRule struct{}

func (defaultVPCRule) ID() string { return RuleDefaultVPCInUse }

func (defaultVPCRule) Info() RuleInfo {
	return RuleInfo{
		ID:    RuleDefaultVPCInUse,
		Title: "Workloads run in the default VPC",
		Description: "The default VPC ships with public subnets that auto-assign public IP addresses " +
			"and a permissive default security group, so anything launched there is one mistake " +
			"away from internet exposure.",
		Remediation: "Create a purpose-built VPC with private subnets, migrate the workloads, and " +
			"delete the default VPC once it is empty.",
		DefaultSeverity: SeverityLow,
		References:      []string{"https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html"},
		Tags:            []string{"network", "hygiene"},
	}
}

func (defaultVPCRule) Evaluate(g *graph.Graph) []Finding {
	contains := map[resource.RelationType]bool{resource.RelContains: true}
	var out []Finding
	for _, vpc := range sortedResources(g, resource.KindVPC) {
		if isDefault, _ := boolAttr(vpc, resource.AttrIsDefaultVPC); !isDefault {
			continue
		}
		var names []string
		for id := range g.ReachableFrom(vpc.ID, contains) {
			if r := g.Resources[id]; r.Kind == resource.KindEC2Instance && activeInstance(r) {
				names = append(names, displayName(r))
			}
		}
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		out = append(out, Finding{
			RuleID:     RuleDefaultVPCInUse,
			ResourceID: vpc.ID,
			Severity:   SeverityLow,
			Title:      fmt.Sprintf("Default VPC %s hosts %d instance(s)", displayName(vpc), len(names)),
			Description: fmt.Sprintf("Instances running in the default VPC: %s.",
				summarizeNames(names, 5)),
		})
	}
	return out
}

func summarizeNames(names []string, max int) string {
	if len(names) <= max {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:max], ", "), len(names)-max)
}

// ---------------------------------------------------------------------------

type s3PublicAccessBlockRule struct{}

func (s3PublicAccessBlockRule) ID() string { return RuleS3PublicAccessBlock }

func (s3PublicAccessBlockRule) Info() RuleInfo {
	return RuleInfo{
		ID:    RuleS3PublicAccessBlock,
		Title: "S3 Block Public Access is not fully enabled",
		Description: "The bucket does not have all four Block Public Access settings turned on, so a " +
			"future ACL or policy change could make it public without any guardrail stopping it.",
		Remediation: "Enable all four Block Public Access settings on the bucket, or account-wide with " +
			"aws s3control put-public-access-block.",
		DefaultSeverity: SeverityMedium,
		References:      []string{"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"},
		Tags:            []string{"storage", "guardrail"},
	}
}

func (s3PublicAccessBlockRule) Evaluate(g *graph.Graph) []Finding {
	var out []Finding
	for _, r := range sortedResources(g, resource.KindS3Bucket) {
		blocked, known := boolAttr(r, resource.AttrPublicAccessBlock)
		if !known || blocked {
			continue
		}
		out = append(out, Finding{
			RuleID:      RuleS3PublicAccessBlock,
			ResourceID:  r.ID,
			Severity:    SeverityMedium,
			Title:       fmt.Sprintf("S3 bucket %s does not block public access", r.Name),
			Description: fmt.Sprintf("Bucket %s has one or more Block Public Access settings disabled.", r.Name),
		})
	}
	return out
}

// DefaultRules returns InfraLens's built-in exposure and topology rules.
func DefaultRules() []Rule {
	return []Rule{
		openSecurityGroupRule{},
		publicS3BucketRule{},
		exposedInstanceRule{},
		imdsv1Rule{},
		unencryptedVolumeRule{},
		unusedSecurityGroupRule{},
		defaultVPCRule{},
		s3PublicAccessBlockRule{},
	}
}
