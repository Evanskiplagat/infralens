package graph

import (
	"testing"

	"infralens/internal/resource"
)

func TestBuildAndReachableFrom(t *testing.T) {
	vpc := resource.Resource{ID: "vpc/1", Kind: resource.KindVPC}
	subnetA := resource.Resource{ID: "subnet/a", Kind: resource.KindSubnet}
	subnetB := resource.Resource{ID: "subnet/b", Kind: resource.KindSubnet}
	instance := resource.Resource{ID: "ec2_instance/i-1", Kind: resource.KindEC2Instance}

	edges := []resource.Edge{
		resource.NewEdge(vpc.ID, subnetA.ID, resource.RelContains),
		resource.NewEdge(vpc.ID, subnetB.ID, resource.RelContains),
		resource.NewEdge(subnetA.ID, instance.ID, resource.RelContains),
	}

	g := Build([]resource.Resource{vpc, subnetA, subnetB, instance}, edges)

	if len(g.Out(vpc.ID)) != 2 {
		t.Fatalf("expected 2 outgoing edges from vpc, got %d", len(g.Out(vpc.ID)))
	}
	if len(g.In(subnetA.ID)) != 1 {
		t.Fatalf("expected 1 incoming edge to subnetA, got %d", len(g.In(subnetA.ID)))
	}

	reachable := g.ReachableFrom(vpc.ID, nil)
	for _, id := range []string{vpc.ID, subnetA.ID, subnetB.ID, instance.ID} {
		if !reachable[id] {
			t.Errorf("expected %s to be reachable from vpc", id)
		}
	}

	restricted := g.ReachableFrom(vpc.ID, map[resource.RelationType]bool{resource.RelAttachedTo: true})
	if len(restricted) != 1 {
		t.Fatalf("expected only the start node when no contains edges are allowed, got %d nodes", len(restricted))
	}
}
