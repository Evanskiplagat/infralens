package findings

import (
	"fmt"

	"infralens/internal/graph"
	"infralens/internal/resource"
)

// Rule IDs, stable across releases so automation can filter on them.
const (
	RuleOpenSecurityGroup = "open_security_group"
	RulePublicS3Bucket    = "public_s3_bucket"
	RuleExposedInstance   = "internet_exposed_instance"
)

// sensitivePorts are flagged as High severity when open to the world;
// any other unrestricted ingress is still reported, at Medium severity.
var sensitivePorts = map[int32]bool{
	22: true, 3389: true, 3306: true, 5432: true, 6379: true, 9200: true, 27017: true,
}

func isOpenCIDR(cidr string) bool {
	return cidr == "0.0.0.0/0" || cidr == "::/0"
}

type openSecurityGroupRule struct{}

func (openSecurityGroupRule) ID() string { return RuleOpenSecurityGroup }

func (openSecurityGroupRule) Evaluate(g *graph.Graph) []Finding {
	var out []Finding
	for _, r := range g.Resources {
		if r.Kind != resource.KindSecurityGroup {
			continue
		}
		for _, rule := range resource.IngressRules(r.Attributes) {
			if !isOpenCIDR(rule.CIDR) {
				continue
			}
			severity := SeverityMedium
			if sensitivePorts[rule.FromPort] || sensitivePorts[rule.ToPort] {
				severity = SeverityHigh
			}
			out = append(out, Finding{
				RuleID:     RuleOpenSecurityGroup,
				ResourceID: r.ID,
				Severity:   severity,
				Title:      fmt.Sprintf("Security group %s allows unrestricted ingress", r.Name),
				Description: fmt.Sprintf(
					"%s permits inbound %s traffic on port(s) %d-%d from %s.",
					r.Name, rule.Protocol, rule.FromPort, rule.ToPort, rule.CIDR,
				),
			})
		}
	}
	return out
}

type publicS3BucketRule struct{}

func (publicS3BucketRule) ID() string { return RulePublicS3Bucket }

func (publicS3BucketRule) Evaluate(g *graph.Graph) []Finding {
	var out []Finding
	for _, r := range g.Resources {
		if r.Kind != resource.KindS3Bucket {
			continue
		}
		if public, _ := r.Attributes[resource.AttrBucketPublic].(bool); public {
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

type exposedInstanceRule struct{}

func (exposedInstanceRule) ID() string { return RuleExposedInstance }

func (exposedInstanceRule) Evaluate(g *graph.Graph) []Finding {
	var out []Finding
	for _, r := range g.Resources {
		if r.Kind != resource.KindEC2Instance {
			continue
		}
		hasPublicIP, _ := r.Attributes[resource.AttrHasPublicIP].(bool)
		if !hasPublicIP || !memberOfOpenSecurityGroup(g, r.ID) {
			continue
		}
		out = append(out, Finding{
			RuleID:      RuleExposedInstance,
			ResourceID:  r.ID,
			Severity:    SeverityHigh,
			Title:       fmt.Sprintf("Instance %s is reachable from the internet", r.Name),
			Description: fmt.Sprintf("%s has a public IP and belongs to a security group with unrestricted ingress.", r.Name),
		})
	}
	return out
}

func memberOfOpenSecurityGroup(g *graph.Graph, instanceID string) bool {
	for _, e := range g.Out(instanceID) {
		if e.Type != resource.RelMemberOf {
			continue
		}
		sg, ok := g.Resources[e.To]
		if !ok {
			continue
		}
		for _, rule := range resource.IngressRules(sg.Attributes) {
			if isOpenCIDR(rule.CIDR) {
				return true
			}
		}
	}
	return false
}

// DefaultRules returns InfraLens's built-in exposure and topology rules.
func DefaultRules() []Rule {
	return []Rule{
		openSecurityGroupRule{},
		publicS3BucketRule{},
		exposedInstanceRule{},
	}
}
