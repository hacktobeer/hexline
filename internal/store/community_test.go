package store

import (
	"errors"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

func commTestStore(t *testing.T) *Store {
	t.Helper()
	st := openTemp(t)
	if err := st.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := st.Seed(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return st
}

func commTestUser(t *testing.T, st *Store, handle string) *domain.User {
	t.Helper()
	u := &domain.User{
		Handle:     handle,
		Role:       domain.RoleUser,
		Status:     domain.StatusActive,
		CreatedAt:  time.Now().UTC(),
		PassHash:   "x",
		PassParams: "x",
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user %s: %v", handle, err)
	}
	return u
}

func TestOnelinersInsertListHide(t *testing.T) {
	st := commTestStore(t)
	ada := commTestUser(t, st, "ada")
	grace := commTestUser(t, st, "grace")

	first := &domain.Oneliner{AuthorID: ada.ID, Body: "first"}
	second := &domain.Oneliner{AuthorID: grace.ID, Body: "second"}
	if err := st.CreateOneliner(first); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateOneliner(second); err != nil {
		t.Fatal(err)
	}
	if first.ID == 0 || second.ID == 0 {
		t.Fatalf("ids not assigned: %d %d", first.ID, second.ID)
	}

	items, err := st.ListOneliners(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 oneliners, got %d", len(items))
	}
	if items[0].ID != second.ID || items[0].Body != "second" {
		t.Fatalf("newest first broken: %+v", items)
	}
	if items[0].Author != "grace" || items[1].Author != "ada" {
		t.Fatalf("author handles not joined: %+v", items)
	}

	if err := st.SetOnelinerHidden(first.ID, true, grace.ID); err != nil {
		t.Fatal(err)
	}
	items, err = st.ListOneliners(10)
	if err != nil {
		t.Fatal(err)
	}
	if !items[1].Hidden {
		t.Fatalf("first oneliner not hidden: %+v", items[1])
	}
	if items[0].Hidden {
		t.Fatalf("second oneliner unexpectedly hidden: %+v", items[0])
	}

	if err := st.SetOnelinerHidden(first.ID, false, grace.ID); err != nil {
		t.Fatal(err)
	}
	items, err = st.ListOneliners(10)
	if err != nil {
		t.Fatal(err)
	}
	if items[1].Hidden {
		t.Fatal("oneliner not restored")
	}

	if err := st.SetOnelinerHidden(999999, true, grace.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing oneliner: want ErrNotFound, got %v", err)
	}
}

func TestPollCreateVoteCountsAndClose(t *testing.T) {
	st := commTestStore(t)
	ada := commTestUser(t, st, "ada")
	grace := commTestUser(t, st, "grace")

	closes := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	p := &domain.Poll{Question: "Tabs or spaces?", CreatedBy: ada.ID, ClosesAt: closes}
	if err := st.CreatePoll(p, []string{"tabs", "spaces", "mixed"}); err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || len(p.Options) != 3 {
		t.Fatalf("poll not created correctly: %+v", p)
	}
	if p.Options[0].ID == 0 || p.Options[1].Label != "spaces" {
		t.Fatalf("option ids/order wrong: %+v", p.Options)
	}

	got, err := st.PollByID(p.ID, ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ClosesAt.Equal(closes) {
		t.Fatalf("closes_at = %v, want %v", got.ClosesAt, closes)
	}
	if got.TotalVotes != 0 || got.MyVote != 0 {
		t.Fatalf("fresh poll has votes: %+v", got)
	}

	now := time.Now().UTC()
	if err := st.Vote(p.ID, p.Options[0].ID, ada.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := st.Vote(p.ID, p.Options[0].ID, grace.ID, now); err != nil {
		t.Fatal(err)
	}

	got, err = st.PollByID(p.ID, ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalVotes != 2 {
		t.Fatalf("total votes = %d, want 2", got.TotalVotes)
	}
	if got.Options[0].Votes != 2 || got.Options[1].Votes != 0 {
		t.Fatalf("option counts wrong: %+v", got.Options)
	}
	if got.MyVote != p.Options[0].ID {
		t.Fatalf("ada my vote = %d, want %d", got.MyVote, p.Options[0].ID)
	}
	gracePoll, err := st.PollByID(p.ID, grace.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gracePoll.MyVote != p.Options[0].ID {
		t.Fatalf("grace my vote = %d, want %d", gracePoll.MyVote, p.Options[0].ID)
	}

	// The primary key (poll_id, user_id) rejects a second vote.
	if err := st.Vote(p.ID, p.Options[1].ID, ada.ID, now); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("double vote: want ErrConflict, got %v", err)
	}
	if err := st.Vote(p.ID, 999999, grace.ID, now); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("foreign option: want ErrInvalid, got %v", err)
	}

	list, err := st.ListPolls(ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != p.ID || list[0].TotalVotes != 2 || list[0].MyVote != p.Options[0].ID {
		t.Fatalf("list polls wrong: %+v", list)
	}
}

func TestBulletinsActiveDismissalsAndOwnership(t *testing.T) {
	st := commTestStore(t)
	ada := commTestUser(t, st, "ada")
	grace := commTestUser(t, st, "grace")

	active := &domain.Bulletin{Title: "Active notice", Body: "hello", Sort: 10, Active: true}
	inactive := &domain.Bulletin{Title: "Retired notice", Body: "old", Sort: 20, Active: false}
	if err := st.CreateBulletin(active); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateBulletin(inactive); err != nil {
		t.Fatal(err)
	}

	live, err := st.ListBulletins(true)
	if err != nil {
		t.Fatal(err)
	}
	if !commHasBulletin(live, active.ID) {
		t.Fatal("active bulletin missing from active list")
	}
	if commHasBulletin(live, inactive.ID) {
		t.Fatal("inactive bulletin leaked into active list")
	}
	all, err := st.ListBulletins(false)
	if err != nil {
		t.Fatal(err)
	}
	if !commHasBulletin(all, inactive.ID) {
		t.Fatal("inactive bulletin missing from full list")
	}

	forAda, err := st.ActiveBulletinsFor(ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !commHasBulletin(forAda, active.ID) {
		t.Fatal("active bulletin missing before dismissal")
	}
	if err := st.DismissBulletin(ada.ID, active.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DismissBulletin(ada.ID, active.ID); err != nil {
		t.Fatalf("dismiss is not idempotent: %v", err)
	}
	forAda, err = st.ActiveBulletinsFor(ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if commHasBulletin(forAda, active.ID) {
		t.Fatal("dismissed bulletin still visible to ada")
	}
	forGrace, err := st.ActiveBulletinsFor(grace.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !commHasBulletin(forGrace, active.ID) {
		t.Fatal("ada's dismissal leaked to grace")
	}

	if err := st.UpdateBulletin(active.ID, "Active notice", "hello again", true, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateBulletin(inactive.ID, "Retired notice", "old", true, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	forGrace, err = st.ActiveBulletinsFor(grace.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !commHasBulletin(forGrace, inactive.ID) {
		t.Fatal("reactivated bulletin missing")
	}

	if err := st.DeleteBulletin(active.ID); err != nil {
		t.Fatal(err)
	}
	forGrace, err = st.ActiveBulletinsFor(grace.ID)
	if err != nil {
		t.Fatal(err)
	}
	if commHasBulletin(forGrace, active.ID) {
		t.Fatal("deleted bulletin still listed")
	}

	if err := st.UpdateBulletin("missing", "x", "y", true, time.Now().UTC()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("update missing: want ErrNotFound, got %v", err)
	}
	if err := st.DeleteBulletin("missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete missing: want ErrNotFound, got %v", err)
	}
	if err := st.DismissBulletin(grace.ID, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("dismiss missing: want ErrNotFound, got %v", err)
	}
}

func commHasBulletin(list []domain.Bulletin, id string) bool {
	for _, b := range list {
		if b.ID == id {
			return true
		}
	}
	return false
}
