// Package normalize converts raw awsdiscovery output into the internal
// resource model (internal/resource), including the structural edges
// (containment, membership, attachment, routing) that the graph and
// findings packages reason over.
package normalize

import (
	"infralens/internal/awsdiscovery"
	"infralens/internal/resource"
)

// Normalize maps a discovery Snapshot into resources and edges, tagging
// every resource with accountID.
func Normalize(accountID string, snap *awsdiscovery.Snapshot) ([]resource.Resource, []resource.Edge) {
	var resources []resource.Resource
	var edges []resource.Edge

	for _, v := range snap.VPCs {
		id := resource.NewID(resource.KindVPC, v.ID)
		resources = append(resources, resource.Resource{
			ID: id, ProviderID: v.ID, Kind: resource.KindVPC, Name: nameOrID(v.Tags, v.ID),
			Region: v.Region, AccountID: accountID, Tags: v.Tags,
			Attributes: map[string]any{
				resource.AttrCIDRBlock:    v.CIDRBlock,
				resource.AttrIsDefaultVPC: v.IsDefault,
			},
		})
	}

	for _, s := range snap.Subnets {
		id := resource.NewID(resource.KindSubnet, s.ID)
		vpcID := resource.NewID(resource.KindVPC, s.VPCID)
		resources = append(resources, resource.Resource{
			ID: id, ProviderID: s.ID, Kind: resource.KindSubnet, Name: nameOrID(s.Tags, s.ID),
			Region: s.Region, AccountID: accountID, Tags: s.Tags,
			Attributes: map[string]any{
				resource.AttrCIDRBlock:        s.CIDRBlock,
				resource.AttrAvailabilityZone: s.AvailabilityZone,
				resource.AttrMapPublicIP:      s.MapPublicIPOnLaunch,
			},
		})
		edges = append(edges, resource.NewEdge(vpcID, id, resource.RelContains))
	}

	for _, rt := range snap.RouteTables {
		id := resource.NewID(resource.KindRouteTable, rt.ID)
		vpcID := resource.NewID(resource.KindVPC, rt.VPCID)
		resources = append(resources, resource.Resource{
			ID: id, ProviderID: rt.ID, Kind: resource.KindRouteTable, Name: nameOrID(rt.Tags, rt.ID),
			Region: rt.Region, AccountID: accountID, Tags: rt.Tags,
			Attributes: map[string]any{resource.AttrHasIGWRoute: rt.HasIGWRoute},
		})
		edges = append(edges, resource.NewEdge(vpcID, id, resource.RelContains))
		for _, subnetID := range rt.SubnetIDs {
			edges = append(edges, resource.NewEdge(id, resource.NewID(resource.KindSubnet, subnetID), resource.RelRoutesTo))
		}
	}

	for _, igw := range snap.InternetGateways {
		id := resource.NewID(resource.KindInternetGateway, igw.ID)
		resources = append(resources, resource.Resource{
			ID: id, ProviderID: igw.ID, Kind: resource.KindInternetGateway, Name: nameOrID(igw.Tags, igw.ID),
			Region: igw.Region, AccountID: accountID, Tags: igw.Tags,
		})
		for _, vpcID := range igw.VPCIDs {
			edges = append(edges, resource.NewEdge(resource.NewID(resource.KindVPC, vpcID), id, resource.RelAttachedTo))
		}
	}

	for _, sg := range snap.SecurityGroups {
		id := resource.NewID(resource.KindSecurityGroup, sg.ID)
		vpcID := resource.NewID(resource.KindVPC, sg.VPCID)
		rules := make([]resource.SGRule, 0, len(sg.Ingress))
		for _, r := range sg.Ingress {
			rules = append(rules, resource.SGRule{Protocol: r.Protocol, FromPort: r.FromPort, ToPort: r.ToPort, CIDR: r.CIDR})
		}
		resources = append(resources, resource.Resource{
			ID: id, ProviderID: sg.ID, Kind: resource.KindSecurityGroup, Name: nameOrID(sg.Tags, sg.Name),
			Region: sg.Region, AccountID: accountID, Tags: sg.Tags,
			Attributes: map[string]any{resource.AttrIngressRules: rules},
		})
		edges = append(edges, resource.NewEdge(vpcID, id, resource.RelContains))
	}

	for _, in := range snap.Instances {
		id := resource.NewID(resource.KindEC2Instance, in.ID)
		resources = append(resources, resource.Resource{
			ID: id, ProviderID: in.ID, Kind: resource.KindEC2Instance, Name: nameOrID(in.Tags, in.ID),
			Region: in.Region, AccountID: accountID, Tags: in.Tags,
			Attributes: map[string]any{
				resource.AttrPublicIP:    in.PublicIP,
				resource.AttrHasPublicIP: in.PublicIP != "",
				resource.AttrState:       in.State,
			},
		})
		if in.SubnetID != "" {
			edges = append(edges, resource.NewEdge(resource.NewID(resource.KindSubnet, in.SubnetID), id, resource.RelContains))
		}
		for _, sgID := range in.SecurityGroupIDs {
			edges = append(edges, resource.NewEdge(id, resource.NewID(resource.KindSecurityGroup, sgID), resource.RelMemberOf))
		}
	}

	for _, b := range snap.S3Buckets {
		id := resource.NewID(resource.KindS3Bucket, b.Name)
		resources = append(resources, resource.Resource{
			ID: id, ProviderID: b.Name, Kind: resource.KindS3Bucket, Name: b.Name,
			Region: b.Region, AccountID: accountID, Tags: b.Tags,
			Attributes: map[string]any{resource.AttrBucketPublic: b.PublicAccess},
		})
	}

	return resources, edges
}

func nameOrID(tags map[string]string, id string) string {
	if name, ok := tags["Name"]; ok && name != "" {
		return name
	}
	return id
}
