package graph

import (
	"fmt"
	"sort"

	"infralens/internal/resource"
)

// Neighborhood selects resources within depth relationships of start, following
// incoming and outgoing edges. The returned edges keep their original direction
// and include all relationships between selected resources. Missing endpoints
// are ignored; they cannot connect otherwise disconnected resources.
func (g *Graph) Neighborhood(start string, depth int) ([]resource.Resource, []resource.Edge, error) {
	if depth < 0 {
		return nil, nil, fmt.Errorf("depth must be non-negative")
	}
	if _, exists := g.Resources[start]; !exists {
		return nil, nil, fmt.Errorf("resource %q not found in scan", start)
	}
	visited := map[string]bool{start: true}
	frontier := []string{start}
	for level := 0; level < depth && len(frontier) > 0; level++ {
		next := make([]string, 0)
		visit := func(id string) {
			if _, exists := g.Resources[id]; exists && !visited[id] {
				visited[id] = true
				next = append(next, id)
			}
		}
		for _, id := range frontier {
			for _, e := range g.out[id] {
				visit(e.To)
			}
			for _, e := range g.in[id] {
				visit(e.From)
			}
		}
		frontier = next
	}

	resources := make([]resource.Resource, 0, len(visited))
	for id := range visited {
		resources = append(resources, g.Resources[id])
	}
	edges := make([]resource.Edge, 0)
	for _, e := range g.Edges {
		if visited[e.From] && visited[e.To] {
			edges = append(edges, e)
		}
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	return resources, edges, nil
}
