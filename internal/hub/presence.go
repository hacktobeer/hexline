package hub

import (
	"sort"
	"sync"
	"time"
)

// Node is a live session slot.
type Node struct {
	ID       string
	UserID   string
	Handle   string
	Node     int
	Activity string
	RemoteIP string
	Started  time.Time
	LastSeen time.Time
}

// Presence tracks who is online. It is in-memory truth; the store keeps
// session rows for forensics only.
type Presence struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	last  int
}

// NewPresence returns an empty registry.
func NewPresence() *Presence {
	return &Presence{nodes: map[string]*Node{}}
}

// Join registers a session and assigns the next node number.
func (p *Presence) Join(id, userID, handle, remoteIP string) *Node {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last++
	n := &Node{
		ID: id, UserID: userID, Handle: handle, Node: p.last,
		Activity: "main menu", RemoteIP: remoteIP,
		Started: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}
	p.nodes[id] = n
	return n
}

// Leave removes a session.
func (p *Presence) Leave(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.nodes, id)
}

// Touch updates activity text and the idle clock.
func (p *Presence) Touch(id, activity string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n, ok := p.nodes[id]; ok {
		n.Activity = activity
		n.LastSeen = time.Now().UTC()
	}
}

// List returns online sessions ordered by node number.
func (p *Presence) List() []Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Node, 0, len(p.nodes))
	for _, n := range p.nodes {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// Count is the number of online sessions.
func (p *Presence) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.nodes)
}
