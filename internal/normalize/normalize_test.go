package normalize

import (
	"testing"

	"infralens/internal/awsdiscovery"
	"infralens/internal/resource"
)

func TestNormalize(t *testing.T) {
	snap := &awsdiscovery.Snapshot{
		VPCs: []awsdiscovery.VPC{
			{ID: "vpc-1", CIDRBlock: "10.0.0.0/16", Region: "us-east-1"},
		},
		Subnets: []awsdiscovery.Subnet{
			{ID: "subnet-1", VPCID: "vpc-1", CIDRBlock: "10.0.1.0/24", Region: "us-east-1"},
		},
		SecurityGroups: []awsdiscovery.SecurityGroup{
			{
				ID: "sg-1", VPCID: "vpc-1", Name: "web",
				Ingress: []awsdiscovery.SecurityGroupRule{
					{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0"},
				},
				Region: "us-east-1",
			},
		},
		Instances: []awsdiscovery.Instance{
			{
				ID: "i-1", VPCID: "vpc-1", SubnetID: "subnet-1",
				SecurityGroupIDs: []string{"sg-1"}, PublicIP: "1.2.3.4",
				Region: "us-east-1",
			},
		},
		S3Buckets: []awsdiscovery.S3Bucket{
			{Name: "my-bucket", PublicAccess: true},
		},
	}

	resources, edges := Normalize("111122223333", snap)

	if len(resources) != 5 {
		t.Fatalf("expected 5 resources, got %d", len(resources))
	}

	byID := map[string]resource.Resource{}
	for _, r := range resources {
		byID[r.ID] = r
		if r.AccountID != "111122223333" {
			t.Errorf("expected resource %s to be tagged with account id, got %q", r.ID, r.AccountID)
		}
	}

	instance, ok := byID[resource.NewID(resource.KindEC2Instance, "i-1")]
	if !ok {
		t.Fatal("expected instance i-1 to be present")
	}
	if hasPublicIP, _ := instance.Attributes[resource.AttrHasPublicIP].(bool); !hasPublicIP {
		t.Error("expected instance to be flagged as having a public IP")
	}

	sg, ok := byID[resource.NewID(resource.KindSecurityGroup, "sg-1")]
	if !ok {
		t.Fatal("expected security group sg-1 to be present")
	}
	rules := resource.IngressRules(sg.Attributes)
	if len(rules) != 1 || rules[0].CIDR != "0.0.0.0/0" {
		t.Errorf("expected sg-1 to carry its open ingress rule, got %+v", rules)
	}

	wantEdgeTypes := map[resource.RelationType]bool{
		resource.RelContains:  false,
		resource.RelMemberOf:  false,
	}
	for _, e := range edges {
		if _, ok := wantEdgeTypes[e.Type]; ok {
			wantEdgeTypes[e.Type] = true
		}
	}
	for relType, seen := range wantEdgeTypes {
		if !seen {
			t.Errorf("expected at least one %s edge", relType)
		}
	}
}
