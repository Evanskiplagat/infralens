// Package diff compares two scans' resources and edges so `infralens
// diff` can report what changed between them.
package diff

import (
	"reflect"
	"sort"

	"infralens/internal/resource"
)

// ResourceChange records a resource whose fields differ between scans.
type ResourceChange struct {
	ID     string
	Before resource.Resource
	After  resource.Resource
}

// ResourceDiff is the result of comparing two scans' resource sets.
type ResourceDiff struct {
	Added     []resource.Resource
	Removed   []resource.Resource
	Changed   []ResourceChange
	Unchanged int
}

// CompareResources diffs resources by their stable Resource.ID.
func CompareResources(from, to []resource.Resource) ResourceDiff {
	fromByID := indexResourcesByID(from)
	toByID := indexResourcesByID(to)

	var d ResourceDiff
	for id, r := range toByID {
		before, existed := fromByID[id]
		switch {
		case !existed:
			d.Added = append(d.Added, r)
		case !reflect.DeepEqual(before, r):
			d.Changed = append(d.Changed, ResourceChange{ID: id, Before: before, After: r})
		default:
			d.Unchanged++
		}
	}
	for id, r := range fromByID {
		if _, ok := toByID[id]; !ok {
			d.Removed = append(d.Removed, r)
		}
	}

	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].ID < d.Added[j].ID })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].ID < d.Removed[j].ID })
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].ID < d.Changed[j].ID })

	return d
}

func indexResourcesByID(rs []resource.Resource) map[string]resource.Resource {
	m := make(map[string]resource.Resource, len(rs))
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

// EdgeDiff is the result of comparing two scans' edge sets.
type EdgeDiff struct {
	Added   []resource.Edge
	Removed []resource.Edge
}

// CompareEdges diffs edges by their deterministic Edge.ID.
func CompareEdges(from, to []resource.Edge) EdgeDiff {
	fromByID := indexEdgesByID(from)
	toByID := indexEdgesByID(to)

	var d EdgeDiff
	for id, e := range toByID {
		if _, ok := fromByID[id]; !ok {
			d.Added = append(d.Added, e)
		}
	}
	for id, e := range fromByID {
		if _, ok := toByID[id]; !ok {
			d.Removed = append(d.Removed, e)
		}
	}

	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].ID < d.Added[j].ID })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].ID < d.Removed[j].ID })

	return d
}

func indexEdgesByID(es []resource.Edge) map[string]resource.Edge {
	m := make(map[string]resource.Edge, len(es))
	for _, e := range es {
		m[e.ID] = e
	}
	return m
}
