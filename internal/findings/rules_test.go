package findings

import (
	"testing"

	"infralens/internal/graph"
	"infralens/internal/resource"
)

func TestDefaultRules(t *testing.T) {
	sg := resource.Resource{
		ID:   "security_group/sg-1",
		Kind: resource.KindSecurityGroup,
		Name: "sg-1",
		Attributes: map[string]any{
			resource.AttrIngressRules: []resource.SGRule{
				{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0"},
			},
		},
	}
	instance := resource.Resource{
		ID:   "ec2_instance/i-1",
		Kind: resource.KindEC2Instance,
		Name: "i-1",
		Attributes: map[string]any{
			resource.AttrHasPublicIP: true,
		},
	}
	privateInstance := resource.Resource{
		ID:   "ec2_instance/i-2",
		Kind: resource.KindEC2Instance,
		Name: "i-2",
		Attributes: map[string]any{
			resource.AttrHasPublicIP: false,
		},
	}
	bucket := resource.Resource{
		ID:   "s3_bucket/my-bucket",
		Kind: resource.KindS3Bucket,
		Name: "my-bucket",
		Attributes: map[string]any{
			resource.AttrBucketPublic: true,
		},
	}

	edges := []resource.Edge{
		resource.NewEdge(instance.ID, sg.ID, resource.RelMemberOf),
		resource.NewEdge(privateInstance.ID, sg.ID, resource.RelMemberOf),
	}

	g := graph.Build([]resource.Resource{sg, instance, privateInstance, bucket}, edges)

	found := Run(g, DefaultRules())

	byRule := map[string]int{}
	for _, f := range found {
		byRule[f.RuleID]++
	}

	if byRule[RuleOpenSecurityGroup] != 1 {
		t.Errorf("expected 1 open security group finding, got %d", byRule[RuleOpenSecurityGroup])
	}
	if byRule[RulePublicS3Bucket] != 1 {
		t.Errorf("expected 1 public bucket finding, got %d", byRule[RulePublicS3Bucket])
	}
	if byRule[RuleExposedInstance] != 1 {
		t.Errorf("expected 1 exposed instance finding, got %d", byRule[RuleExposedInstance])
	}

	for _, f := range found {
		if f.RuleID == RuleExposedInstance && f.ResourceID != instance.ID {
			t.Errorf("expected exposed instance finding on %s, got %s", instance.ID, f.ResourceID)
		}
	}
}
