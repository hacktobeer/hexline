package hub

import (
	"testing"
	"time"
)

func TestSubscribersReceiveMatchingScopes(t *testing.T) {
	b := NewBroker(8)
	all, cancelAll := b.Subscribe("*")
	defer cancelAll()
	global, cancelGlobal := b.Subscribe("chat:global")
	defer cancelGlobal()

	b.Publish(Event{Kind: KindChat, Scope: "chat:global", Text: "hello"})
	b.Publish(Event{Kind: KindChat, Scope: "chat:sysop", Text: "mods only"})
	b.Publish(Event{Kind: KindNotice, Scope: "user:123", Text: "notice"})

	got := drain(all, 3)
	if len(got) != 3 {
		t.Fatalf("wildcard subscriber got %d events, want 3", len(got))
	}
	got = drain(global, 3)
	if len(got) != 1 || got[0].Text != "hello" {
		t.Fatalf("global subscriber got %+v", got)
	}

	cancelAll()
	if _, ok := <-all; ok {
		t.Fatal("cancelled subscription channel was not closed")
	}
	b.Publish(Event{Scope: "chat:global", Text: "after cancel"})
	select {
	case ev := <-global:
		if ev.Text != "after cancel" {
			t.Fatalf("unexpected event %q", ev.Text)
		}
	case <-time.After(time.Second):
		t.Fatal("surviving subscriber stopped receiving after another cancel")
	}
}

func TestSlowSubscriberKeepsNewestEvents(t *testing.T) {
	b := NewBroker(2)
	ch, cancel := b.Subscribe("*")
	defer cancel()

	for i := 0; i < 5; i++ {
		b.Publish(Event{Scope: "chat:global", Text: string(rune('a' + i))})
	}
	got := drain(ch, 2)
	if len(got) != 2 || got[0].Text != "d" || got[1].Text != "e" {
		t.Fatalf("kept %+v, want the two newest (d, e)", got)
	}
}

func TestPresenceTracksNodes(t *testing.T) {
	p := NewPresence()
	first := p.Join("s1", "u1", "ada", "ip1")
	second := p.Join("s2", "u2", "grace", "ip2")
	if first.Node >= second.Node {
		t.Fatalf("node numbers did not increase: %d then %d", first.Node, second.Node)
	}
	if p.Count() != 2 {
		t.Fatalf("count = %d", p.Count())
	}
	if list := p.List(); len(list) != 2 || list[0].Handle != "ada" || list[1].Handle != "grace" {
		t.Fatalf("list = %+v", list)
	}

	before := first.LastSeen
	p.Touch("s1", "reading /general")
	list := p.List()
	if list[0].Activity != "reading /general" {
		t.Fatalf("activity = %q", list[0].Activity)
	}
	if list[0].LastSeen.Before(before) {
		t.Fatal("touch moved last seen backwards")
	}

	p.Leave("s1")
	if p.Count() != 1 {
		t.Fatalf("count after leave = %d", p.Count())
	}
	p.Leave("missing") // must not panic or change the count
	if p.Count() != 1 {
		t.Fatalf("count after unknown leave = %d", p.Count())
	}
	if b := bLen(p); b != 1 {
		t.Fatalf("registry holds %d nodes", b)
	}
}

// bLen reports the registry size through List to keep the test independent of
// internal fields.
func bLen(p *Presence) int { return len(p.List()) }

func drain(ch <-chan Event, want int) []Event {
	var out []Event
	for len(out) < want {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
		case <-time.After(time.Second):
			return out
		}
	}
	return out
}
