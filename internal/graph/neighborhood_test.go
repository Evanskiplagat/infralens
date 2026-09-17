package graph

import (
	"reflect"
	"testing"

	"infralens/internal/resource"
)

func TestNeighborhood(t *testing.T) {
	resources := []resource.Resource{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}, {ID: "isolated"}}
	edges := []resource.Edge{
		resource.NewEdge("b", "a", resource.RelContains),
		resource.NewEdge("a", "c", resource.RelMemberOf),
		resource.NewEdge("c", "b", resource.RelAttachedTo),
		resource.NewEdge("c", "d", resource.RelContains),
		resource.NewEdge("a", "missing", resource.RelContains),
		resource.NewEdge("missing", "isolated", resource.RelContains),
	}
	g := Build(resources, edges)
	for _, tt := range []struct {
		name  string
		start string
		depth int
		ids   []string
		edges int
	}{
		{"zero", "a", 0, []string{"a"}, 0},
		{"both directions and boundary edges", "a", 1, []string{"a", "b", "c"}, 3},
		{"two hops", "a", 2, []string{"a", "b", "c", "d"}, 4},
		{"cycles and missing endpoints", "a", 100, []string{"a", "b", "c", "d"}, 4},
		{"isolated", "isolated", 100, []string{"isolated"}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, gotEdges, err := g.Neighborhood(tt.start, tt.depth)
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, 0, len(got))
			for _, r := range got {
				ids = append(ids, r.ID)
			}
			if !reflect.DeepEqual(ids, tt.ids) || len(gotEdges) != tt.edges {
				t.Fatalf("got resources %v and %d edges; want %v and %d", ids, len(gotEdges), tt.ids, tt.edges)
			}
			for i, e := range gotEdges {
				if i > 0 && gotEdges[i-1].ID > e.ID {
					t.Fatal("edges are not sorted")
				}
				if e != resource.NewEdge(e.From, e.To, e.Type) {
					t.Fatal("edge direction or identity changed")
				}
			}
			if gotEdges == nil {
				t.Fatal("empty edges must encode as [] rather than null")
			}
		})
	}
	if len(g.Resources) != len(resources) || !reflect.DeepEqual(g.Edges, edges) {
		t.Fatal("selection mutated the source graph")
	}
}

func TestNeighborhoodInvalidInput(t *testing.T) {
	g := Build([]resource.Resource{{ID: "a"}}, nil)
	if _, _, err := g.Neighborhood("missing", 1); err == nil {
		t.Fatal("expected unknown resource error")
	}
	if _, _, err := g.Neighborhood("a", -1); err == nil {
		t.Fatal("expected negative depth error")
	}
}
