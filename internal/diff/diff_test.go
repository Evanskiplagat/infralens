package diff

import (
	"testing"

	"infralens/internal/resource"
)

func TestCompareResources(t *testing.T) {
	kept := resource.Resource{ID: "ec2_instance/i-1", Name: "kept"}
	removed := resource.Resource{ID: "ec2_instance/i-2", Name: "removed"}
	changedBefore := resource.Resource{ID: "ec2_instance/i-3", Name: "before"}
	changedAfter := resource.Resource{ID: "ec2_instance/i-3", Name: "after"}
	added := resource.Resource{ID: "ec2_instance/i-4", Name: "added"}

	from := []resource.Resource{kept, removed, changedBefore}
	to := []resource.Resource{kept, changedAfter, added}

	d := CompareResources(from, to)

	if len(d.Added) != 1 || d.Added[0].ID != added.ID {
		t.Fatalf("expected added=[%s], got %+v", added.ID, d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].ID != removed.ID {
		t.Fatalf("expected removed=[%s], got %+v", removed.ID, d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[0].After.Name != "after" {
		t.Fatalf("expected one change to i-3, got %+v", d.Changed)
	}
	if d.Unchanged != 1 {
		t.Fatalf("expected 1 unchanged resource, got %d", d.Unchanged)
	}
}

func TestCompareEdges(t *testing.T) {
	kept := resource.NewEdge("a", "b", resource.RelContains)
	removed := resource.NewEdge("a", "c", resource.RelContains)
	added := resource.NewEdge("a", "d", resource.RelContains)

	from := []resource.Edge{kept, removed}
	to := []resource.Edge{kept, added}

	d := CompareEdges(from, to)

	if len(d.Added) != 1 || d.Added[0].ID != added.ID {
		t.Fatalf("expected added=[%s], got %+v", added.ID, d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].ID != removed.ID {
		t.Fatalf("expected removed=[%s], got %+v", removed.ID, d.Removed)
	}
}
