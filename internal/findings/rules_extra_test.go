package findings

import (
	"strings"
	"testing"

	"infralens/internal/graph"
	"infralens/internal/resource"
)

// topology builds vpc -> subnet -> instance with an optional route table and
// internet gateway, returning the graph and the instance ID.
type topologyOpts struct {
	routeTable    bool // create a route table
	igwRoute      bool // route table has a route to an IGW
	explicitAssoc bool // route table is explicitly associated to the subnet
	main          bool // route table is the VPC's main table
	igwAttached   bool
	ports         []resource.SGRule
	publicIP      bool
	state         string
}

func buildTopology(o topologyOpts) (*graph.Graph, string) {
	vpc := resource.Resource{ID: "vpc/vpc-1", ProviderID: "vpc-1", Kind: resource.KindVPC}
	subnet := resource.Resource{ID: "subnet/subnet-1", ProviderID: "subnet-1", Kind: resource.KindSubnet}
	sg := resource.Resource{
		ID: "security_group/sg-1", ProviderID: "sg-1", Kind: resource.KindSecurityGroup, Name: "web",
		Attributes: map[string]any{resource.AttrIngressRules: o.ports},
	}
	attrs := map[string]any{resource.AttrHasPublicIP: o.publicIP}
	if o.state != "" {
		attrs[resource.AttrState] = o.state
	}
	inst := resource.Resource{ID: "ec2_instance/i-1", ProviderID: "i-1", Kind: resource.KindEC2Instance, Name: "app", Attributes: attrs}

	resources := []resource.Resource{vpc, subnet, sg, inst}
	edges := []resource.Edge{
		resource.NewEdge(vpc.ID, subnet.ID, resource.RelContains),
		resource.NewEdge(subnet.ID, inst.ID, resource.RelContains),
		resource.NewEdge(inst.ID, sg.ID, resource.RelMemberOf),
	}
	if o.routeTable {
		rt := resource.Resource{
			ID: "route_table/rtb-1", ProviderID: "rtb-1", Kind: resource.KindRouteTable,
			Attributes: map[string]any{
				resource.AttrHasIGWRoute:      o.igwRoute,
				resource.AttrIsMainRouteTable: o.main,
			},
		}
		resources = append(resources, rt)
		edges = append(edges, resource.NewEdge(vpc.ID, rt.ID, resource.RelContains))
		if o.explicitAssoc {
			edges = append(edges, resource.NewEdge(rt.ID, subnet.ID, resource.RelRoutesTo))
		}
	}
	if o.igwAttached {
		igw := resource.Resource{ID: "internet_gateway/igw-1", ProviderID: "igw-1", Kind: resource.KindInternetGateway}
		resources = append(resources, igw)
		edges = append(edges, resource.NewEdge(vpc.ID, igw.ID, resource.RelAttachedTo))
	}
	return graph.Build(resources, edges), inst.ID
}

func findRule(fs []Finding, ruleID string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func TestSeverityRank(t *testing.T) {
	order := AllSeverities()
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Fatalf("%s should outrank %s", order[i], order[i-1])
		}
	}
	if Severity("bogus").Valid() || Severity("bogus").Rank() >= SeverityInfo.Rank() {
		t.Fatal("unknown severities must not validate or outrank info")
	}
	if !SeverityCritical.Valid() {
		t.Fatal("critical must be a valid severity")
	}
}

func TestOpenSecurityGroupSeverities(t *testing.T) {
	tests := []struct {
		name string
		rule resource.SGRule
		want Severity
	}{
		{"all traffic", resource.SGRule{Protocol: "-1", CIDR: "0.0.0.0/0"}, SeverityCritical},
		{"all tcp ports", resource.SGRule{Protocol: "tcp", FromPort: 0, ToPort: 65535, CIDR: "::/0"}, SeverityCritical},
		{"ssh", resource.SGRule{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0"}, SeverityHigh},
		{"range covering postgres", resource.SGRule{Protocol: "tcp", FromPort: 5000, ToPort: 6000, CIDR: "0.0.0.0/0"}, SeverityHigh},
		{"https", resource.SGRule{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0"}, SeverityMedium},
		{"udp on ssh port is not ssh", resource.SGRule{Protocol: "udp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0"}, SeverityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sg := resource.Resource{
				ID: "security_group/sg-1", Kind: resource.KindSecurityGroup, Name: "sg-1",
				Attributes: map[string]any{resource.AttrIngressRules: []resource.SGRule{tt.rule}},
			}
			got := findRule(Run(graph.Build([]resource.Resource{sg}, nil), DefaultRules()), RuleOpenSecurityGroup)
			if len(got) != 1 || got[0].Severity != tt.want {
				t.Fatalf("got %+v, want one %s finding", got, tt.want)
			}
		})
	}

	closed := resource.Resource{
		ID: "security_group/sg-2", Kind: resource.KindSecurityGroup, Name: "sg-2",
		Attributes: map[string]any{resource.AttrIngressRules: []resource.SGRule{
			{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "10.0.0.0/8"},
		}},
	}
	if got := findRule(Run(graph.Build([]resource.Resource{closed}, nil), DefaultRules()), RuleOpenSecurityGroup); len(got) != 0 {
		t.Fatalf("private CIDR must not be flagged: %+v", got)
	}
}

func TestExposedInstanceUsesRouteEvidence(t *testing.T) {
	ssh := []resource.SGRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0"}}
	web := []resource.SGRule{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0"}}

	tests := []struct {
		name     string
		opts     topologyOpts
		want     Severity
		evidence string
	}{
		{
			name:     "confirmed path with sensitive port is critical",
			opts:     topologyOpts{routeTable: true, igwRoute: true, explicitAssoc: true, igwAttached: true, ports: ssh, publicIP: true},
			want:     SeverityCritical,
			evidence: "internet -> igw-1 -> vpc-1 -> rtb-1 -> subnet-1 -> i-1",
		},
		{
			name:     "confirmed path with ordinary port is high",
			opts:     topologyOpts{routeTable: true, igwRoute: true, explicitAssoc: true, igwAttached: true, ports: web, publicIP: true},
			want:     SeverityHigh,
			evidence: "internet -> igw-1",
		},
		{
			name:     "main route table applies when subnet has no association",
			opts:     topologyOpts{routeTable: true, igwRoute: true, main: true, igwAttached: true, ports: ssh, publicIP: true},
			want:     SeverityCritical,
			evidence: "rtb-1",
		},
		{
			name:     "route table without igw route lowers severity",
			opts:     topologyOpts{routeTable: true, igwRoute: false, explicitAssoc: true, ports: ssh, publicIP: true},
			want:     SeverityMedium,
			evidence: "no route to an internet gateway",
		},
		{
			name:     "no route data is not treated as safe",
			opts:     topologyOpts{ports: ssh, publicIP: true},
			want:     SeverityHigh,
			evidence: "no route table data",
		},
		{
			name:     "non-main table without association is unknown, not safe",
			opts:     topologyOpts{routeTable: true, igwRoute: true, ports: ssh, publicIP: true},
			want:     SeverityHigh,
			evidence: "no route table data",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, _ := buildTopology(tt.opts)
			got := findRule(Run(g, DefaultRules()), RuleExposedInstance)
			if len(got) != 1 {
				t.Fatalf("want one finding, got %+v", got)
			}
			if got[0].Severity != tt.want {
				t.Errorf("severity = %s, want %s (%s)", got[0].Severity, tt.want, got[0].Description)
			}
			if !strings.Contains(got[0].Description, tt.evidence) {
				t.Errorf("description %q should contain %q", got[0].Description, tt.evidence)
			}
		})
	}
}

func TestExposedInstanceRequiresPublicIPAndOpenIngress(t *testing.T) {
	ssh := []resource.SGRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0"}}
	private := []resource.SGRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "10.0.0.0/8"}}

	for name, o := range map[string]topologyOpts{
		"no public ip":   {ports: ssh, publicIP: false},
		"closed ingress": {ports: private, publicIP: true},
		"terminated":     {ports: ssh, publicIP: true, state: "terminated"},
	} {
		g, _ := buildTopology(o)
		if got := findRule(Run(g, DefaultRules()), RuleExposedInstance); len(got) != 0 {
			t.Errorf("%s: unexpected finding %+v", name, got)
		}
	}
}

func TestInternetPathDescribe(t *testing.T) {
	if got := (InternetPath{State: RouteUnknown}).Describe("i-1"); !strings.Contains(got, "no route table data") {
		t.Errorf("unknown path description = %q", got)
	}
	got := InternetPath{State: RouteInternet, Gateway: "igw-1", Subnet: "subnet-1"}.Describe("i-1")
	if got != "internet -> igw-1 -> subnet-1 -> i-1" {
		t.Errorf("partial path should skip missing hops, got %q", got)
	}
	for _, s := range []RouteState{RouteUnknown, RouteNone, RouteInternet} {
		if s.String() == "" {
			t.Errorf("state %d has no name", s)
		}
	}
}

func TestIMDSv1Rule(t *testing.T) {
	mk := func(id string, attrs map[string]any) resource.Resource {
		return resource.Resource{ID: "ec2_instance/" + id, Kind: resource.KindEC2Instance, Name: id, Attributes: attrs}
	}
	g := graph.Build([]resource.Resource{
		mk("v1-plain", map[string]any{resource.AttrIMDSv2Required: false}),
		mk("v1-exposed", map[string]any{
			resource.AttrIMDSv2Required:     false,
			resource.AttrHasPublicIP:        true,
			resource.AttrIAMInstanceProfile: "arn:aws:iam::1:instance-profile/app",
		}),
		mk("v2", map[string]any{resource.AttrIMDSv2Required: true}),
		mk("unknown", map[string]any{}),
		mk("v1-terminated", map[string]any{resource.AttrIMDSv2Required: false, resource.AttrState: "terminated"}),
	}, nil)

	got := findRule(Run(g, DefaultRules()), RuleIMDSv1Enabled)
	bySeverity := map[string]Severity{}
	for _, f := range got {
		bySeverity[f.ResourceID] = f.Severity
	}
	want := map[string]Severity{
		"ec2_instance/v1-exposed": SeverityHigh,
		"ec2_instance/v1-plain":   SeverityMedium,
	}
	if len(bySeverity) != len(want) {
		t.Fatalf("got %v, want %v", bySeverity, want)
	}
	for id, sev := range want {
		if bySeverity[id] != sev {
			t.Errorf("%s severity = %s, want %s", id, bySeverity[id], sev)
		}
	}
}

func TestUnencryptedVolumeRule(t *testing.T) {
	inst := resource.Resource{ID: "ec2_instance/i-1", ProviderID: "i-1", Kind: resource.KindEC2Instance, Name: "app"}
	bad := resource.Resource{ID: "ebs_volume/vol-1", Kind: resource.KindEBSVolume, Name: "vol-1", Attributes: map[string]any{resource.AttrEncrypted: false}}
	good := resource.Resource{ID: "ebs_volume/vol-2", Kind: resource.KindEBSVolume, Name: "vol-2", Attributes: map[string]any{resource.AttrEncrypted: true}}
	unknown := resource.Resource{ID: "ebs_volume/vol-3", Kind: resource.KindEBSVolume, Name: "vol-3"}
	g := graph.Build([]resource.Resource{inst, bad, good, unknown},
		[]resource.Edge{resource.NewEdge(bad.ID, inst.ID, resource.RelAttachedTo)})

	got := findRule(Run(g, DefaultRules()), RuleUnencryptedVolume)
	if len(got) != 1 || got[0].ResourceID != bad.ID {
		t.Fatalf("want only vol-1 flagged, got %+v", got)
	}
	if !strings.Contains(got[0].Description, "attached to i-1") {
		t.Errorf("description should name the attached instance: %q", got[0].Description)
	}
}

func TestUnusedSecurityGroupRule(t *testing.T) {
	sg := func(id, name string) resource.Resource {
		return resource.Resource{
			ID: "security_group/" + id, Kind: resource.KindSecurityGroup, Name: id,
			Attributes: map[string]any{resource.AttrGroupName: name},
		}
	}
	inst := resource.Resource{ID: "ec2_instance/i-1", Kind: resource.KindEC2Instance}
	used, referenced, orphan, def := sg("sg-used", "web"), sg("sg-ref", "db"), sg("sg-orphan", "old"), sg("sg-default", "default")
	g := graph.Build(
		[]resource.Resource{used, referenced, orphan, def, inst},
		[]resource.Edge{
			resource.NewEdge(inst.ID, used.ID, resource.RelMemberOf),
			resource.NewEdge(used.ID, referenced.ID, resource.RelReferences),
		})

	got := findRule(Run(g, DefaultRules()), RuleUnusedSecurityGroup)
	if len(got) != 1 || got[0].ResourceID != orphan.ID || got[0].Severity != SeverityInfo {
		t.Fatalf("want only the orphan group flagged at info, got %+v", got)
	}
}

func TestDefaultVPCRule(t *testing.T) {
	newVPC := func(id string, isDefault bool) resource.Resource {
		return resource.Resource{
			ID: "vpc/" + id, ProviderID: id, Kind: resource.KindVPC,
			Attributes: map[string]any{resource.AttrIsDefaultVPC: isDefault},
		}
	}
	defVPC, otherVPC := newVPC("vpc-default", true), newVPC("vpc-custom", false)
	emptyDefault := newVPC("vpc-empty", true)
	subnetA := resource.Resource{ID: "subnet/a", Kind: resource.KindSubnet}
	subnetB := resource.Resource{ID: "subnet/b", Kind: resource.KindSubnet}
	instA := resource.Resource{ID: "ec2_instance/i-a", ProviderID: "i-a", Kind: resource.KindEC2Instance}
	instB := resource.Resource{ID: "ec2_instance/i-b", ProviderID: "i-b", Kind: resource.KindEC2Instance}
	g := graph.Build(
		[]resource.Resource{defVPC, otherVPC, emptyDefault, subnetA, subnetB, instA, instB},
		[]resource.Edge{
			resource.NewEdge(defVPC.ID, subnetA.ID, resource.RelContains),
			resource.NewEdge(subnetA.ID, instA.ID, resource.RelContains),
			resource.NewEdge(otherVPC.ID, subnetB.ID, resource.RelContains),
			resource.NewEdge(subnetB.ID, instB.ID, resource.RelContains),
		})

	got := findRule(Run(g, DefaultRules()), RuleDefaultVPCInUse)
	if len(got) != 1 || got[0].ResourceID != defVPC.ID {
		t.Fatalf("want only the populated default VPC flagged, got %+v", got)
	}
	if !strings.Contains(got[0].Description, "i-a") || strings.Contains(got[0].Description, "i-b") {
		t.Errorf("description should list only the default VPC's instances: %q", got[0].Description)
	}
}

func TestS3PublicAccessBlockRule(t *testing.T) {
	mk := func(name string, attrs map[string]any) resource.Resource {
		return resource.Resource{ID: "s3_bucket/" + name, Kind: resource.KindS3Bucket, Name: name, Attributes: attrs}
	}
	g := graph.Build([]resource.Resource{
		mk("open", map[string]any{resource.AttrPublicAccessBlock: false}),
		mk("blocked", map[string]any{resource.AttrPublicAccessBlock: true}),
		mk("unknown", map[string]any{}),
	}, nil)
	got := findRule(Run(g, DefaultRules()), RuleS3PublicAccessBlock)
	if len(got) != 1 || got[0].ResourceID != "s3_bucket/open" {
		t.Fatalf("want only the bucket without a full block flagged, got %+v", got)
	}
}

func TestRunOrdersFindingsDeterministically(t *testing.T) {
	sg := func(id string, rule resource.SGRule) resource.Resource {
		return resource.Resource{
			ID: "security_group/" + id, Kind: resource.KindSecurityGroup, Name: id,
			Attributes: map[string]any{resource.AttrIngressRules: []resource.SGRule{rule}},
		}
	}
	resources := []resource.Resource{
		sg("sg-c", resource.SGRule{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0"}),
		sg("sg-a", resource.SGRule{Protocol: "-1", CIDR: "0.0.0.0/0"}),
		sg("sg-b", resource.SGRule{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDR: "0.0.0.0/0"}),
	}
	first := Run(graph.Build(resources, nil), []Rule{openSecurityGroupRule{}})
	wantOrder := []Severity{SeverityCritical, SeverityHigh, SeverityMedium}
	for i, f := range first {
		if f.Severity != wantOrder[i] {
			t.Fatalf("finding %d severity = %s, want %s", i, f.Severity, wantOrder[i])
		}
	}
	for i := 0; i < 20; i++ {
		again := Run(graph.Build(resources, nil), []Rule{openSecurityGroupRule{}})
		for j := range again {
			if again[j] != first[j] {
				t.Fatalf("run %d produced a different order at %d", i, j)
			}
		}
	}
}

func TestCatalogIsCompleteAndConsistent(t *testing.T) {
	rules := DefaultRules()
	seen := map[string]bool{}
	for _, r := range rules {
		info := r.Info()
		if info.ID != r.ID() {
			t.Errorf("rule %q reports info for %q", r.ID(), info.ID)
		}
		if seen[info.ID] {
			t.Errorf("duplicate rule ID %q", info.ID)
		}
		seen[info.ID] = true
		if info.Title == "" || info.Description == "" || info.Remediation == "" {
			t.Errorf("rule %q needs a title, description and remediation", info.ID)
		}
		if !info.DefaultSeverity.Valid() {
			t.Errorf("rule %q has invalid default severity %q", info.ID, info.DefaultSeverity)
		}
		for _, ref := range info.References {
			if !strings.HasPrefix(ref, "https://") {
				t.Errorf("rule %q reference %q must be https", info.ID, ref)
			}
		}
	}
	catalog := Catalog(rules)
	for i := 1; i < len(catalog); i++ {
		if catalog[i-1].ID >= catalog[i].ID {
			t.Fatalf("catalog not sorted: %s before %s", catalog[i-1].ID, catalog[i].ID)
		}
	}
	if _, ok := LookupRule(RuleExposedInstance); !ok {
		t.Error("LookupRule should find built-in rules")
	}
	if _, ok := LookupRule("nope"); ok {
		t.Error("LookupRule should not find unknown rules")
	}
}
