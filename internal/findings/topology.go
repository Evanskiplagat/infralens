package findings

import (
	"sort"
	"strings"

	"infralens/internal/graph"
	"infralens/internal/resource"
)

// RouteState is what a scan can prove about a subnet's route to the
// internet. Discovery is read-only and best-effort, so "we found no route"
// and "we have no route data" are deliberately different answers.
type RouteState int

const (
	// RouteUnknown means the graph has no route table information for the
	// subnet, so nothing can be concluded either way.
	RouteUnknown RouteState = iota
	// RouteNone means route tables govern the subnet and none of them
	// sends traffic to an internet gateway.
	RouteNone
	// RouteInternet means a route table governing the subnet has a route
	// to an internet gateway.
	RouteInternet
)

func (s RouteState) String() string {
	switch s {
	case RouteNone:
		return "no internet route"
	case RouteInternet:
		return "internet route"
	default:
		return "unknown route"
	}
}

// InternetPath is the evidence trail from the internet to an instance:
// internet gateway, VPC, route table and subnet. Fields are the display
// names of the resources involved and are empty when not established.
type InternetPath struct {
	State      RouteState
	Gateway    string
	VPC        string
	RouteTable string
	Subnet     string
}

// Describe renders the path as "internet -> igw -> vpc -> rtb -> subnet ->
// target", or a short explanation when there is no confirmed path.
func (p InternetPath) Describe(target string) string {
	switch p.State {
	case RouteInternet:
		hops := []string{"internet"}
		for _, hop := range []string{p.Gateway, p.VPC, p.RouteTable, p.Subnet, target} {
			if hop != "" {
				hops = append(hops, hop)
			}
		}
		return strings.Join(hops, " -> ")
	case RouteNone:
		return "subnet " + p.Subnet + " has no route to an internet gateway"
	default:
		return "no route table data for the instance's subnet"
	}
}

// InternetPathFor traces how (and whether) an EC2 instance's subnet routes
// to the internet, using only relationships already in the graph:
//
//	subnet -contains-> instance
//	route table -routes_to-> subnet   (explicit association)
//	vpc -contains-> route table       (the main table applies when a subnet
//	                                   has no explicit association)
//	vpc -attached_to-> internet gateway
func InternetPathFor(g *graph.Graph, instanceID string) InternetPath {
	subnet, ok := parentOfKind(g, instanceID, resource.KindSubnet)
	if !ok {
		return InternetPath{}
	}
	path := InternetPath{Subnet: displayName(subnet)}

	vpc, hasVPC := parentOfKind(g, subnet.ID, resource.KindVPC)
	if hasVPC {
		path.VPC = displayName(vpc)
	}

	tables := routeTablesFor(g, subnet, vpc, hasVPC)
	if len(tables) == 0 {
		path.State = RouteUnknown
		return path
	}

	for _, rt := range tables {
		if routes, _ := rt.Attributes[resource.AttrHasIGWRoute].(bool); !routes {
			continue
		}
		path.State = RouteInternet
		path.RouteTable = displayName(rt)
		if hasVPC {
			path.Gateway = attachedGateway(g, vpc.ID)
		}
		return path
	}
	path.State = RouteNone
	return path
}

// parentOfKind finds the resource of the given kind that contains id.
func parentOfKind(g *graph.Graph, id string, kind resource.Kind) (resource.Resource, bool) {
	for _, e := range g.In(id) {
		if e.Type != resource.RelContains {
			continue
		}
		if parent, ok := g.Resources[e.From]; ok && parent.Kind == kind {
			return parent, true
		}
	}
	return resource.Resource{}, false
}

// routeTablesFor returns the route tables that govern a subnet: its
// explicit associations, or the VPC's main table(s) when it has none.
func routeTablesFor(g *graph.Graph, subnet, vpc resource.Resource, hasVPC bool) []resource.Resource {
	var tables []resource.Resource
	for _, e := range g.In(subnet.ID) {
		if e.Type != resource.RelRoutesTo {
			continue
		}
		if rt, ok := g.Resources[e.From]; ok && rt.Kind == resource.KindRouteTable {
			tables = append(tables, rt)
		}
	}
	if len(tables) == 0 && hasVPC {
		for _, e := range g.Out(vpc.ID) {
			if e.Type != resource.RelContains {
				continue
			}
			rt, ok := g.Resources[e.To]
			if !ok || rt.Kind != resource.KindRouteTable {
				continue
			}
			if main, _ := rt.Attributes[resource.AttrIsMainRouteTable].(bool); main {
				tables = append(tables, rt)
			}
		}
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].ID < tables[j].ID })
	return tables
}

// attachedGateway returns the display name of an internet gateway attached
// to the VPC, or "" when the graph does not contain one.
func attachedGateway(g *graph.Graph, vpcID string) string {
	var names []string
	for _, e := range g.Out(vpcID) {
		if e.Type != resource.RelAttachedTo {
			continue
		}
		if igw, ok := g.Resources[e.To]; ok && igw.Kind == resource.KindInternetGateway {
			names = append(names, displayName(igw))
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// displayName prefers the provider's own ID (i-0abc, sg-123) because it is
// what operators search for, and falls back to the human name.
func displayName(r resource.Resource) string {
	if r.ProviderID != "" {
		return r.ProviderID
	}
	if r.Name != "" {
		return r.Name
	}
	return r.ID
}
