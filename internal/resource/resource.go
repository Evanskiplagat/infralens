// Package resource defines InfraLens's internal representation of AWS
// infrastructure: the normalized Resource and Edge types every other
// package (graph, findings, storage, export) builds on. Raw AWS SDK
// shapes never leave the awsdiscovery package; everything downstream of
// normalize works only with these types.
package resource

import "fmt"

// Kind identifies the normalized type of a discovered resource.
type Kind string

const (
	KindVPC              Kind = "vpc"
	KindSubnet           Kind = "subnet"
	KindRouteTable       Kind = "route_table"
	KindInternetGateway  Kind = "internet_gateway"
	KindSecurityGroup    Kind = "security_group"
	KindEC2Instance      Kind = "ec2_instance"
	KindS3Bucket         Kind = "s3_bucket"
)

// Resource is a single normalized piece of AWS infrastructure discovered
// during a scan. Attributes holds kind-specific data (see attributes.go
// for the recognized keys) so that Resource itself stays generic.
type Resource struct {
	ID         string
	ProviderID string
	Kind       Kind
	Name       string
	Region     string
	AccountID  string
	Tags       map[string]string
	Attributes map[string]any
}

// NewID builds the stable, scan-independent identifier used to correlate
// the same physical AWS resource across scans (for diffing) and as the
// primary key within a single scan's graph.
func NewID(kind Kind, providerID string) string {
	return fmt.Sprintf("%s/%s", kind, providerID)
}

// RelationType identifies how two resources relate to each other.
type RelationType string

const (
	// RelContains models structural nesting, e.g. VPC -> Subnet.
	RelContains RelationType = "contains"
	// RelMemberOf models group membership, e.g. Instance -> SecurityGroup.
	RelMemberOf RelationType = "member_of"
	// RelAttachedTo models attachment, e.g. VPC -> InternetGateway.
	RelAttachedTo RelationType = "attached_to"
	// RelRoutesTo models routing, e.g. RouteTable -> Subnet.
	RelRoutesTo RelationType = "routes_to"
)

// Edge is a directed relationship between two resources, identified by
// their Resource.ID values.
type Edge struct {
	ID   string
	From string
	To   string
	Type RelationType
}

// NewEdge builds an Edge with a deterministic ID, so the same logical
// relationship produces the same ID across scans and can be diffed.
func NewEdge(from, to string, t RelationType) Edge {
	return Edge{
		ID:   fmt.Sprintf("%s--%s-->%s", from, t, to),
		From: from,
		To:   to,
		Type: t,
	}
}
