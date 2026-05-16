// Package graph maintains the gsnet topology: nodes, edges between them, and
// the subnets each node owns. It is the in-memory mirror of the gossip state.
//
// Edges are stored undirected: AddEdge("a","b") and AddEdge("b","a") refer to
// the same edge — an edge represents bidirectional reachability between two
// daemons.
package graph

import (
	"sync"
)

// Edge represents one direction of a connection between two nodes. We store
// both halves (a->b and b->a) so the graph always reflects symmetric
// reachability without callers having to manage the inverse explicitly.
type Edge struct {
	From   string
	To     string
	Weight int // lower = preferred
}

type nodeData struct {
	subnets map[string]struct{}
}

// Graph is the in-memory topology state.
type Graph struct {
	mu sync.RWMutex

	nodes map[string]*nodeData
	// adjacency: nodes[from][to] = edge
	adj map[string]map[string]Edge
}

func New() *Graph {
	return &Graph{
		nodes: make(map[string]*nodeData),
		adj:   make(map[string]map[string]Edge),
	}
}

func (g *Graph) AddNode(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ensureNode(name)
}

func (g *Graph) ensureNode(name string) *nodeData {
	if n, ok := g.nodes[name]; ok {
		return n
	}
	n := &nodeData{subnets: make(map[string]struct{})}
	g.nodes[name] = n
	g.adj[name] = make(map[string]Edge)
	return n
}

func (g *Graph) HasNode(name string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	_, ok := g.nodes[name]
	return ok
}

func (g *Graph) Nodes() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]string, 0, len(g.nodes))
	for n := range g.nodes {
		out = append(out, n)
	}
	return out
}

func (g *Graph) AddEdge(e Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ensureNode(e.From)
	g.ensureNode(e.To)
	g.adj[e.From][e.To] = e
	rev := Edge{From: e.To, To: e.From, Weight: e.Weight}
	g.adj[e.To][e.From] = rev
}

func (g *Graph) DelEdge(from, to string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if m, ok := g.adj[from]; ok {
		delete(m, to)
	}
	if m, ok := g.adj[to]; ok {
		delete(m, from)
	}
}

func (g *Graph) HasEdge(from, to string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if m, ok := g.adj[from]; ok {
		_, ok := m[to]
		return ok
	}
	return false
}

func (g *Graph) Edges() []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []Edge
	for _, m := range g.adj {
		for _, e := range m {
			out = append(out, e)
		}
	}
	return out
}

// Reachable returns the set of nodes reachable from start, including start
// itself if it exists. Uses BFS over the adjacency map.
func (g *Graph) Reachable(start string) map[string]struct{} {
	g.mu.RLock()
	defer g.mu.RUnlock()
	visited := make(map[string]struct{})
	if _, ok := g.nodes[start]; !ok {
		return visited
	}
	queue := []string{start}
	visited[start] = struct{}{}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for next := range g.adj[n] {
			if _, seen := visited[next]; seen {
				continue
			}
			visited[next] = struct{}{}
			queue = append(queue, next)
		}
	}
	return visited
}

func (g *Graph) AddSubnet(owner, subnet string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := g.ensureNode(owner)
	n.subnets[subnet] = struct{}{}
}

func (g *Graph) DelSubnet(owner, subnet string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n, ok := g.nodes[owner]; ok {
		delete(n.subnets, subnet)
	}
}

func (g *Graph) NodeSubnets(name string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[name]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(n.subnets))
	for s := range n.subnets {
		out = append(out, s)
	}
	return out
}

// SubnetOwner returns the node that owns subnet, if any.
func (g *Graph) SubnetOwner(subnet string) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for name, n := range g.nodes {
		if _, ok := n.subnets[subnet]; ok {
			return name, true
		}
	}
	return "", false
}

// AllSubnets returns subnet → owner.
func (g *Graph) AllSubnets() map[string]string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make(map[string]string)
	for name, n := range g.nodes {
		for s := range n.subnets {
			out[s] = name
		}
	}
	return out
}
