package normalize

import (
	"testing"

	"infralens/internal/awsdiscovery"
	"infralens/internal/findings"
	"infralens/internal/graph"
	"infralens/internal/resource"
)

func boolPtr(b bool) *bool { return &b }

func edgeSet(edges []resource.Edge) map[string]bool {
	set := make(map[string]bool, len(edges))
	for _, e := range edges {
		set[e.ID] = true
	}
	return set
}

func TestNormalizeRicherDiscoveryData(t *testing.T) {
	snap := &awsdiscovery.Snapshot{
		VPCs:    []awsdiscovery.VPC{{ID: "vpc-1", IsDefault: true, Region: "us-east-1"}},
		Subnets: []awsdiscovery.Subnet{{ID: "subnet-1", VPCID: "vpc-1", Region: "us-east-1"}},
		RouteTables: []awsdiscovery.RouteTable{
			{ID: "rtb-main", VPCID: "vpc-1", HasIGWRoute: true, IsMain: true, Region: "us-east-1"},
		},
		InternetGateways: []awsdiscovery.InternetGateway{{ID: "igw-1", VPCIDs: []string{"vpc-1"}, Region: "us-east-1"}},
		SecurityGroups: []awsdiscovery.SecurityGroup{
			{ID: "sg-web", VPCID: "vpc-1", Name: "web", Ingress: []awsdiscovery.SecurityGroupRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0"}}, ReferencedGroupIDs: []string{"sg-db"}},
			{ID: "sg-db", VPCID: "vpc-1", Name: "default"},
		},
		Instances: []awsdiscovery.Instance{
			{ID: "i-1", VPCID: "vpc-1", SubnetID: "subnet-1", SecurityGroupIDs: []string{"sg-web"}, PublicIP: "203.0.113.7",
				State: "running", InstanceType: "t3.micro", IAMInstanceProfileARN: "arn:aws:iam::1:instance-profile/app", HTTPTokens: "optional", Region: "us-east-1"},
			{ID: "i-2", VPCID: "vpc-1", SubnetID: "subnet-1", HTTPTokens: "required", Region: "us-east-1"},
			{ID: "i-3", VPCID: "vpc-1", SubnetID: "subnet-1", Region: "us-east-1"}, // API reported no setting
		},
		Volumes: []awsdiscovery.Volume{
			{ID: "vol-1", Encrypted: false, SizeGiB: 100, VolumeType: "gp3", AttachedInstanceIDs: []string{"i-1"}, Region: "us-east-1"},
		},
		S3Buckets: []awsdiscovery.S3Bucket{
			{Name: "blocked", BlockPublicAccess: boolPtr(true)},
			{Name: "open", BlockPublicAccess: boolPtr(false)},
			{Name: "unknown"},
		},
	}

	resources, edges := Normalize("111122223333", snap)
	byID := map[string]resource.Resource{}
	for _, r := range resources {
		byID[r.ID] = r
	}
	got := edgeSet(edges)

	rtb := byID["route_table/rtb-main"]
	if main, _ := rtb.Attributes[resource.AttrIsMainRouteTable].(bool); !main {
		t.Error("main route table flag lost")
	}

	if !got[resource.NewEdge("security_group/sg-web", "security_group/sg-db", resource.RelReferences).ID] {
		t.Error("missing security group reference edge")
	}
	if name, _ := byID["security_group/sg-db"].Attributes[resource.AttrGroupName].(string); name != "default" {
		t.Errorf("group name = %q", name)
	}

	i1 := byID["ec2_instance/i-1"]
	if v, ok := i1.Attributes[resource.AttrIMDSv2Required].(bool); !ok || v {
		t.Errorf("optional tokens should mean IMDSv2 not required, got %v (present=%v)", v, ok)
	}
	if v, _ := byID["ec2_instance/i-2"].Attributes[resource.AttrIMDSv2Required].(bool); !v {
		t.Error("required tokens should mean IMDSv2 required")
	}
	if _, present := byID["ec2_instance/i-3"].Attributes[resource.AttrIMDSv2Required]; present {
		t.Error("an unreported IMDS setting must stay absent so rules do not guess")
	}
	if i1.Attributes[resource.AttrInstanceType] != "t3.micro" ||
		i1.Attributes[resource.AttrIAMInstanceProfile] != "arn:aws:iam::1:instance-profile/app" {
		t.Errorf("instance attributes = %v", i1.Attributes)
	}

	vol := byID["ebs_volume/vol-1"]
	if vol.Kind != resource.KindEBSVolume || vol.Attributes[resource.AttrEncrypted] != false || vol.Attributes[resource.AttrSizeGiB] != int32(100) {
		t.Errorf("volume = %+v", vol)
	}
	if !got[resource.NewEdge("ebs_volume/vol-1", "ec2_instance/i-1", resource.RelAttachedTo).ID] {
		t.Error("missing volume attachment edge")
	}

	if v, ok := byID["s3_bucket/blocked"].Attributes[resource.AttrPublicAccessBlock].(bool); !ok || !v {
		t.Error("fully blocked bucket should be recorded as blocked")
	}
	if v, ok := byID["s3_bucket/open"].Attributes[resource.AttrPublicAccessBlock].(bool); !ok || v {
		t.Error("bucket without a full block should be recorded as not blocked")
	}
	if _, present := byID["s3_bucket/unknown"].Attributes[resource.AttrPublicAccessBlock]; present {
		t.Error("an undetermined block setting must stay absent")
	}
}

// TestNormalizedDataDrivesFindings runs the real pipeline from discovery
// output to findings, guarding the attribute contract between normalize and
// the rules (a renamed attribute would silently disable a rule).
func TestNormalizedDataDrivesFindings(t *testing.T) {
	snap := &awsdiscovery.Snapshot{
		VPCs:    []awsdiscovery.VPC{{ID: "vpc-1", IsDefault: true}},
		Subnets: []awsdiscovery.Subnet{{ID: "subnet-1", VPCID: "vpc-1"}},
		RouteTables: []awsdiscovery.RouteTable{
			{ID: "rtb-1", VPCID: "vpc-1", SubnetIDs: []string{"subnet-1"}, HasIGWRoute: true},
		},
		InternetGateways: []awsdiscovery.InternetGateway{{ID: "igw-1", VPCIDs: []string{"vpc-1"}}},
		SecurityGroups: []awsdiscovery.SecurityGroup{
			{ID: "sg-1", VPCID: "vpc-1", Name: "web", Ingress: []awsdiscovery.SecurityGroupRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0"}}},
			{ID: "sg-2", VPCID: "vpc-1", Name: "orphan"},
		},
		Instances: []awsdiscovery.Instance{
			{ID: "i-1", VPCID: "vpc-1", SubnetID: "subnet-1", SecurityGroupIDs: []string{"sg-1"}, PublicIP: "203.0.113.7",
				State: "running", IAMInstanceProfileARN: "arn:aws:iam::1:instance-profile/app", HTTPTokens: "optional"},
		},
		Volumes:   []awsdiscovery.Volume{{ID: "vol-1", AttachedInstanceIDs: []string{"i-1"}}},
		S3Buckets: []awsdiscovery.S3Bucket{{Name: "logs", BlockPublicAccess: boolPtr(false)}},
	}

	resources, edges := Normalize("111122223333", snap)
	found := findings.Run(graph.Build(resources, edges), findings.DefaultRules())

	got := map[string]findings.Severity{}
	for _, f := range found {
		got[f.RuleID+"@"+f.ResourceID] = f.Severity
	}
	want := map[string]findings.Severity{
		"open_security_group@security_group/sg-1":        findings.SeverityHigh,
		"internet_exposed_instance@ec2_instance/i-1":     findings.SeverityCritical, // sensitive port + confirmed IGW route
		"imdsv1_enabled@ec2_instance/i-1":                findings.SeverityHigh,     // profile + public IP
		"unencrypted_ebs_volume@ebs_volume/vol-1":        findings.SeverityMedium,
		"unused_security_group@security_group/sg-2":      findings.SeverityInfo,
		"default_vpc_in_use@vpc/vpc-1":                   findings.SeverityLow,
		"s3_public_access_block_disabled@s3_bucket/logs": findings.SeverityMedium,
	}
	for key, sev := range want {
		if got[key] != sev {
			t.Errorf("%s = %q, want %q", key, got[key], sev)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("unexpected finding %s", key)
		}
	}
}
