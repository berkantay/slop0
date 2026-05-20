package rules

import (
	"sort"
	"testing"
)

func TestTarjanSCC(t *testing.T) {
	tests := []struct {
		name      string
		graph     map[string][]string
		nodes     []string
		wantSCCs  int
		wantMaxSz int
	}{
		{
			"cycle of 3",
			map[string][]string{"A": {"B"}, "B": {"C"}, "C": {"A"}},
			[]string{"A", "B", "C"},
			1,
			3,
		},
		{
			"no cycle",
			map[string][]string{"A": {"B"}, "B": {"C"}},
			[]string{"A", "B", "C"},
			3,
			1,
		},
		{
			"two separate cycles",
			map[string][]string{"A": {"B"}, "B": {"A"}, "C": {"D"}, "D": {"C"}},
			[]string{"A", "B", "C", "D"},
			2,
			2,
		},
		{
			"single node",
			map[string][]string{},
			[]string{"A"},
			1,
			1,
		},
		{
			"self loop",
			map[string][]string{"A": {"A"}},
			[]string{"A"},
			1,
			1,
		},
		{
			"diamond with back edge",
			map[string][]string{"A": {"B", "C"}, "B": {"D"}, "C": {"D"}, "D": {"A"}},
			[]string{"A", "B", "C", "D"},
			1,
			4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sccs := tarjanSCC(tt.graph, tt.nodes)
			if len(sccs) != tt.wantSCCs {
				t.Errorf("tarjanSCC() returned %d SCCs, want %d", len(sccs), tt.wantSCCs)
			}
			maxSz := 0
			for _, scc := range sccs {
				if len(scc) > maxSz {
					maxSz = len(scc)
				}
			}
			if maxSz != tt.wantMaxSz {
				t.Errorf("tarjanSCC() largest SCC size = %d, want %d", maxSz, tt.wantMaxSz)
			}
		})
	}
}

func TestBrandesBetweenness(t *testing.T) {
	tests := []struct {
		name     string
		graph    map[string][]string
		nodes    []string
		wantHigh []string
	}{
		{
			"linear chain with center",
			map[string][]string{"A": {"B"}, "B": {"C"}, "C": {"D"}, "D": {"E"}},
			[]string{"A", "B", "C", "D", "E"},
			[]string{"B", "C", "D"},
		},
		{
			"linear chain",
			map[string][]string{"A": {"B"}, "B": {"C"}, "C": {"D"}},
			[]string{"A", "B", "C", "D"},
			[]string{"B", "C"},
		},
		{
			"single node",
			map[string][]string{},
			[]string{"A"},
			[]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bc := brandesBetweenness(tt.graph, tt.nodes)
			for _, high := range tt.wantHigh {
				if bc[high] <= 0 {
					t.Errorf("brandesBetweenness() expected %s to have positive betweenness, got %f", high, bc[high])
				}
			}
		})
	}
}

func TestBrandesBetweennessLinearOrder(t *testing.T) {
	graph := map[string][]string{"A": {"B"}, "B": {"C"}, "C": {"D"}, "D": {"E"}}
	nodes := []string{"A", "B", "C", "D", "E"}
	bc := brandesBetweenness(graph, nodes)

	if bc["B"] <= bc["A"] {
		t.Errorf("B should have higher betweenness than A: B=%f A=%f", bc["B"], bc["A"])
	}
	if bc["C"] <= bc["A"] {
		t.Errorf("C should have higher betweenness than A: C=%f A=%f", bc["C"], bc["A"])
	}
}

func TestBuildCallGraph(t *testing.T) {
	graph, nodes := buildCallGraph(nil)
	if len(graph) != 0 {
		t.Errorf("buildCallGraph(nil) should return empty graph, got %d entries", len(graph))
	}
	if len(nodes) != 0 {
		t.Errorf("buildCallGraph(nil) should return empty nodes, got %d entries", len(nodes))
	}
}

func TestFindCoupledClusters(t *testing.T) {
	graph := map[string][]string{"A": {"B"}, "B": {"C"}, "C": {"A"}}
	nodes := []string{"A", "B", "C"}
	clusters := findCoupledClusters(graph, nodes)
	if len(clusters) != 1 {
		t.Fatalf("findCoupledClusters() returned %d clusters, want 1", len(clusters))
	}
	if clusters[0].Size != 3 {
		t.Errorf("cluster size = %d, want 3", clusters[0].Size)
	}
	sort.Strings(clusters[0].Nodes)
	want := []string{"A", "B", "C"}
	for i, n := range clusters[0].Nodes {
		if n != want[i] {
			t.Errorf("cluster node %d = %s, want %s", i, n, want[i])
		}
	}
}

func TestFindCoupledClustersNoCycle(t *testing.T) {
	graph := map[string][]string{"A": {"B"}, "B": {"C"}}
	nodes := []string{"A", "B", "C"}
	clusters := findCoupledClusters(graph, nodes)
	if len(clusters) != 0 {
		t.Errorf("findCoupledClusters() with no cycles returned %d clusters, want 0", len(clusters))
	}
}

func TestBfsCount(t *testing.T) {
	tests := []struct {
		name  string
		graph map[string][]string
		start string
		want  int
	}{
		{
			"linear",
			map[string][]string{"A": {"B"}, "B": {"C"}},
			"A",
			2,
		},
		{
			"isolated",
			map[string][]string{},
			"A",
			0,
		},
		{
			"branching",
			map[string][]string{"A": {"B", "C"}, "B": {"D"}, "C": {"D"}},
			"A",
			3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bfsCount(tt.start, tt.graph)
			if got != tt.want {
				t.Errorf("bfsCount(%q) = %d, want %d", tt.start, got, tt.want)
			}
		})
	}
}
