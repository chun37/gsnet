package graph

import (
	"reflect"
	"sort"
	"testing"
)

func TestGraph_AddNode(t *testing.T) {
	g := New()
	g.AddNode("a")
	g.AddNode("b")
	if !g.HasNode("a") {
		t.Errorf("a missing")
	}
	if got := g.Nodes(); !equalStrSets(got, []string{"a", "b"}) {
		t.Errorf("Nodes = %v, want [a b]", got)
	}
}

func TestGraph_AddEdge(t *testing.T) {
	g := New()
	g.AddEdge(Edge{From: "a", To: "b", Weight: 10})
	if !g.HasEdge("a", "b") {
		t.Errorf("a-b missing")
	}
	if !g.HasNode("a") || !g.HasNode("b") {
		t.Errorf("AddEdge did not implicitly add nodes")
	}
}

func TestGraph_DelEdge(t *testing.T) {
	g := New()
	g.AddEdge(Edge{From: "a", To: "b", Weight: 10})
	g.DelEdge("a", "b")
	if g.HasEdge("a", "b") {
		t.Errorf("a-b still present after DelEdge")
	}
}

func TestReachable_Connected(t *testing.T) {
	g := New()
	g.AddEdge(Edge{From: "a", To: "b", Weight: 10})
	g.AddEdge(Edge{From: "b", To: "c", Weight: 10})
	r := g.Reachable("a")
	want := []string{"a", "b", "c"}
	got := setToSorted(r)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Reachable(a) = %v, want %v", got, want)
	}
}

func TestReachable_Disconnected(t *testing.T) {
	g := New()
	g.AddEdge(Edge{From: "a", To: "b", Weight: 10})
	g.AddNode("c")
	r := g.Reachable("a")
	if _, ok := r["c"]; ok {
		t.Errorf("c reported reachable from a, expected not")
	}
}

func TestSubnetOwnership(t *testing.T) {
	g := New()
	g.AddSubnet("a", "192.168.1.0/24")
	g.AddSubnet("b", "192.168.2.0/24")
	if got, _ := g.SubnetOwner("192.168.1.0/24"); got != "a" {
		t.Errorf("SubnetOwner = %q, want a", got)
	}
	g.DelSubnet("a", "192.168.1.0/24")
	if _, ok := g.SubnetOwner("192.168.1.0/24"); ok {
		t.Errorf("subnet still owned after delete")
	}
}

func TestNodeSubnets(t *testing.T) {
	g := New()
	g.AddSubnet("a", "192.168.1.0/24")
	g.AddSubnet("a", "10.0.0.0/8")
	g.AddSubnet("b", "172.16.0.0/12")
	got := g.NodeSubnets("a")
	sort.Strings(got)
	want := []string{"10.0.0.0/8", "192.168.1.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NodeSubnets(a) = %v, want %v", got, want)
	}
}

func setToSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStrSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string{}, a...)
	bs := append([]string{}, b...)
	sort.Strings(as)
	sort.Strings(bs)
	return reflect.DeepEqual(as, bs)
}
