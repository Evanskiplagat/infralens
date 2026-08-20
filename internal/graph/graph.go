// Package graph builds an in-memory relationship graph from normalized
// resources and edges, and provides traversal primitives that findings
// rules use to reason about topology (e.g. "is this instance reachable
// from a security group with open ingress?").
package graph

import "infralens/internal/resource"

// Graph is an adjacency-indexed view over a scan's resources and edges.
type Graph struct {
	Resources map[string]resource.Resource
	Edges     []resource.Edge

	out map[string][]resource.Edge
	in  map[string][]resource.Edge
}

// Build indexes resources and edges for traversal. Edges referencing an
// unknown resource ID are kept (so partial data still round-trips) but
// simply won't be reachable as a traversal source.
func Build(resources []resource.Resource, edges []resource.Edge) *Graph {
	g := &Graph{
		Resources: make(map[string]resource.Resource, len(resources)),
		Edges:     edges,
		out:       make(map[string][]resource.Edge),
		in:        make(map[string][]resource.Edge),
	}
	for _, r := range resources {
		g.Resources[r.ID] = r
	}
	for _, e := range edges {
		g.out[e.From] = append(g.out[e.From], e)
		g.in[e.To] = append(g.in[e.To], e)
	}
	return g
}

// Out returns the edges leading out of id.
func (g *Graph) Out(id string) []resource.Edge { return g.out[id] }

// In returns the edges leading into id.
func (g *Graph) In(id string) []resource.Edge { return g.in[id] }

// ReachableFrom returns the set of resource IDs reachable from start by
// following outgoing edges, including start itself. If allowed is
// non-empty, only edges whose Type is in allowed are followed.
func (g *Graph) ReachableFrom(start string, allowed map[resource.RelationType]bool) map[string]bool {
	visited := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, e := range g.out[id] {
			if len(allowed) > 0 && !allowed[e.Type] {
				continue
			}
			if !visited[e.To] {
				visited[e.To] = true
				queue = append(queue, e.To)
			}
		}
	}
	return visited
}
