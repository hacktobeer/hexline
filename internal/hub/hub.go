// Package hub is hexline's in-process event broker: presence, chat and
// notifications. Subscribers never block publishers; slow consumers lose
// the oldest events instead of stalling a session.
package hub

import (
	"strings"
	"sync"
	"time"
)

// Kind classifies an event.
type Kind string

// Event kinds.
const (
	KindPresence Kind = "presence"
	KindChat     Kind = "chat"
	KindNotice   Kind = "notice"
)

// Event is a single publishable fact.
type Event struct {
	Kind   Kind
	Scope  string // "*", "chat:global", "chat:sysop", "user:<id>"
	FromID string
	From   string
	Text   string
	At     time.Time
}

// Broker fans events out to subscribers by scope prefix.
type Broker struct {
	mu     sync.RWMutex
	subs   map[int]*subscriber
	nextID int
	buffer int
}

type subscriber struct {
	ch     chan Event
	scopes []string
}

// NewBroker creates a broker whose subscriber channels hold buffer events.
func NewBroker(buffer int) *Broker {
	if buffer <= 0 {
		buffer = 32
	}
	return &Broker{subs: map[int]*subscriber{}, buffer: buffer}
}

// Subscribe returns a channel receiving events matching any of scopes.
// Scope "*" matches everything. Call the returned cancel func when done.
func (b *Broker) Subscribe(scopes ...string) (<-chan Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextID
	b.nextID++
	s := &subscriber{ch: make(chan Event, b.buffer), scopes: scopes}
	b.subs[id] = s
	return s.ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if sub, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(sub.ch)
		}
	}
}

// Publish delivers ev to every matching subscriber without blocking.
func (b *Broker) Publish(ev Event) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.subs {
		if !matches(s.scopes, ev.Scope) {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			// Drop oldest, then retry once: chat history is best-effort.
			select {
			case <-s.ch:
			default:
			}
			select {
			case s.ch <- ev:
			default:
			}
		}
	}
}

func matches(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == "*" || s == scope || strings.HasPrefix(scope, s+":") {
			return true
		}
	}
	return false
}

// SubscriptionCount reports live subscribers (used by metrics and tests).
func (b *Broker) SubscriptionCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
