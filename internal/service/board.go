package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/render"
	"github.com/hacktobeer/hexline/internal/store"
)

// Boards implements message areas, threads, posts, read tracking and search.
type Boards struct {
	st  *store.Store
	cfg *config.Config
	now func() time.Time
}

// NewBoards wires the board service.
func NewBoards(st *store.Store, cfg *config.Config) *Boards {
	return &Boards{st: st, cfg: cfg, now: func() time.Time { return time.Now().UTC() }}
}

// SetClock replaces the service clock (tests).
func (b *Boards) SetClock(fn func() time.Time) { b.now = fn }

// boardRole is the role used for ACL checks. Guests are anonymous readers, so
// they are evaluated as ordinary users for read access; write paths are still
// guarded by User.CanWrite.
func boardRole(u *domain.User) domain.Role {
	if u == nil || u.IsGuest {
		return domain.RoleUser
	}
	if !u.Role.Valid() {
		return domain.RoleUser
	}
	return u.Role
}

func boardUserID(u *domain.User) string {
	if u == nil {
		return ""
	}
	return u.ID
}

func boardCanRead(a *domain.Area, u *domain.User) bool {
	if a == nil || !a.ACL.CanRead(boardRole(u)) {
		return false
	}
	// Non-public areas are hidden from anonymous readers (guest, pending
	// registration). Registered callers see them per the ACL.
	if !a.IsPublic && boardAnonymous(u) {
		return false
	}
	return true
}

// boardAnonymous reports a caller who has not completed registration.
func boardAnonymous(u *domain.User) bool {
	return u == nil || u.IsGuest || u.ID == ""
}

func boardCanPost(a *domain.Area, u *domain.User) bool {
	return a != nil && a.ACL.CanPost(boardRole(u))
}

func boardCanModerate(a *domain.Area, u *domain.User) bool {
	return a != nil && a.ACL.CanModerate(boardRole(u))
}

func boardWriter(u *domain.User) error {
	if u == nil || !u.CanWrite() {
		return fmt.Errorf("%w: guests and suspended accounts cannot post", domain.ErrPermission)
	}
	return nil
}

func boardHasLink(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "http://") ||
		strings.Contains(lower, "https://") ||
		strings.Contains(lower, "www.")
}

func (b *Boards) boardPrepareSubject(subject string) (string, error) {
	subject = render.SanitizeLine(subject)
	if err := domain.ValidateSubject(subject); err != nil {
		return "", err
	}
	return subject, nil
}

func (b *Boards) boardPrepareBody(body string) (string, error) {
	body = strings.TrimSpace(render.Sanitize(body))
	if err := domain.ValidateBody(body, b.cfg.Limits.PostMaxBytes, b.cfg.Limits.MaxBodyLines); err != nil {
		return "", err
	}
	return body, nil
}

func (b *Boards) boardCheckContentPolicy(u *domain.User, body string) error {
	if u != nil && u.IsProbation() && boardHasLink(body) {
		return fmt.Errorf("%w: links are disabled while on probation", domain.ErrProbation)
	}
	return nil
}

func (b *Boards) boardCheckRate(u *domain.User) error {
	limit := b.cfg.Limits.PostRatePerHour
	if limit <= 0 || u == nil || u.ID == "" {
		return nil
	}
	count, err := b.st.CountPostsByUserSince(u.ID, b.now().Add(-time.Hour))
	if err != nil {
		return err
	}
	if count >= limit {
		return fmt.Errorf("%w: %d posts in the last hour (limit %d)", domain.ErrRateLimited, count, limit)
	}
	return nil
}

func (b *Boards) boardLoadThread(threadID string, u *domain.User) (*domain.Thread, *domain.Area, error) {
	thread, err := b.st.ThreadByID(threadID, boardUserID(u))
	if err != nil {
		return nil, nil, err
	}
	area, err := b.st.BoardAreaByID(thread.AreaID)
	if err != nil {
		return nil, nil, err
	}
	if !boardCanRead(area, u) {
		return nil, nil, fmt.Errorf("%w: area %q is not readable", domain.ErrPermission, area.Tag)
	}
	if thread.Deleted && !boardCanModerate(area, u) {
		return nil, nil, domain.ErrNotFound
	}
	return thread, area, nil
}

func (b *Boards) boardLoadPost(postID int64, u *domain.User) (*domain.Post, *domain.Thread, *domain.Area, error) {
	post, err := b.st.PostByID(postID)
	if err != nil {
		return nil, nil, nil, err
	}
	thread, area, err := b.boardLoadThread(post.ThreadID, u)
	if err != nil {
		return nil, nil, nil, err
	}
	if post.Deleted && !boardCanModerate(area, u) {
		return nil, nil, nil, domain.ErrNotFound
	}
	return post, thread, area, nil
}

func (b *Boards) boardAudit(actor *domain.User, action, targetKind, targetID string, detail map[string]any) error {
	entry := domain.AuditEntry{Action: action, TargetKind: targetKind, TargetID: targetID}
	if actor != nil {
		entry.ActorID, entry.Actor = actor.ID, actor.Handle
	}
	if len(detail) > 0 {
		raw, err := json.Marshal(detail)
		if err != nil {
			return err
		}
		entry.Detail = string(raw)
	}
	return b.st.RecordAudit(entry)
}

// Areas returns the areas the user may read, in display order.
func (b *Boards) Areas(ctx context.Context, u *domain.User) ([]domain.Area, error) {
	all, err := b.st.BoardListAreas()
	if err != nil {
		return nil, err
	}
	out := make([]domain.Area, 0, len(all))
	for _, a := range all {
		if boardCanRead(&a, u) {
			out = append(out, a)
		}
	}
	return out, nil
}

// AreaByTag loads one area after an ACL check. Unreadable areas look denied,
// not missing, so callers get a clear message.
func (b *Boards) AreaByTag(ctx context.Context, u *domain.User, tag string) (*domain.Area, error) {
	area, err := b.st.BoardAreaByTag(strings.TrimSpace(tag))
	if err != nil {
		return nil, err
	}
	if !boardCanRead(area, u) {
		return nil, fmt.Errorf("%w: area %q is not readable", domain.ErrPermission, area.Tag)
	}
	return area, nil
}

// Threads returns one page of threads in an area with per-user unread counts.
func (b *Boards) Threads(ctx context.Context, u *domain.User, areaID string, limit, offset int) ([]domain.Thread, error) {
	area, err := b.st.BoardAreaByID(areaID)
	if err != nil {
		return nil, err
	}
	if !boardCanRead(area, u) {
		return nil, fmt.Errorf("%w: area %q is not readable", domain.ErrPermission, area.Tag)
	}
	return b.st.ListThreads(area.ID, boardUserID(u), limit, offset)
}

// Thread loads a thread and its posts. Deleted posts (and deleted threads)
// are only visible to moderators of the area.
func (b *Boards) Thread(ctx context.Context, u *domain.User, threadID string) (*domain.Thread, []domain.Post, error) {
	thread, area, err := b.boardLoadThread(threadID, u)
	if err != nil {
		return nil, nil, err
	}
	includeDeleted := boardCanModerate(area, u)
	posts, err := b.st.PostsByThreadPage(thread.ID, 0, boardThreadPageSize, includeDeleted)
	if err != nil {
		return nil, nil, err
	}
	return thread, posts, nil
}

// CreateThread validates, sanitizes and stores a new thread plus its first
// post. Posting is rate limited per user.
func (b *Boards) CreateThread(ctx context.Context, u *domain.User, areaID, subject, body string) (*domain.Thread, error) {
	if err := boardWriter(u); err != nil {
		return nil, err
	}
	area, err := b.st.BoardAreaByID(areaID)
	if err != nil {
		return nil, err
	}
	if !boardCanPost(area, u) {
		return nil, fmt.Errorf("%w: you cannot post in %q", domain.ErrPermission, area.Tag)
	}
	subject, err = b.boardPrepareSubject(subject)
	if err != nil {
		return nil, err
	}
	body, err = b.boardPrepareBody(body)
	if err != nil {
		return nil, err
	}
	if err := b.boardCheckContentPolicy(u, body); err != nil {
		return nil, err
	}
	if err := b.boardCheckRate(u); err != nil {
		return nil, err
	}
	thread, err := b.st.CreateThread(area.ID, u.ID, subject, body, b.now())
	if err != nil {
		return nil, err
	}
	// Authors have read their own post; no unread badge for your own writing.
	_ = b.MarkRead(ctx, u, thread.ID)
	return thread, nil
}

// Reply appends a post to an unlocked thread.
func (b *Boards) Reply(ctx context.Context, u *domain.User, threadID, body string) (*domain.Post, error) {
	if err := boardWriter(u); err != nil {
		return nil, err
	}
	thread, area, err := b.boardLoadThread(threadID, u)
	if err != nil {
		return nil, err
	}
	if !boardCanPost(area, u) {
		return nil, fmt.Errorf("%w: you cannot post in %q", domain.ErrPermission, area.Tag)
	}
	if thread.Locked {
		return nil, fmt.Errorf("%w: %q is locked", domain.ErrClosed, thread.Subject)
	}
	body, err = b.boardPrepareBody(body)
	if err != nil {
		return nil, err
	}
	if err := b.boardCheckContentPolicy(u, body); err != nil {
		return nil, err
	}
	if err := b.boardCheckRate(u); err != nil {
		return nil, err
	}
	post, err := b.st.CreatePost(thread.ID, u.ID, body, b.now())
	if err != nil {
		return nil, err
	}
	_ = b.MarkRead(ctx, u, thread.ID)
	return post, nil
}

// EditPost updates the body of a live post. Authors may edit their own posts;
// area moderators may edit any post in their area.
func (b *Boards) EditPost(ctx context.Context, u *domain.User, postID int64, body string) error {
	if u == nil || !u.CanWrite() {
		return fmt.Errorf("%w: guests and suspended accounts cannot edit", domain.ErrPermission)
	}
	post, thread, area, err := b.boardLoadPost(postID, u)
	if err != nil {
		return err
	}
	if post.AuthorID != u.ID && !boardCanModerate(area, u) {
		return fmt.Errorf("%w: you can only edit your own posts", domain.ErrPermission)
	}
	if thread.Locked && !boardCanModerate(area, u) {
		return fmt.Errorf("%w: %q is locked", domain.ErrClosed, thread.Subject)
	}
	body, err = b.boardPrepareBody(body)
	if err != nil {
		return err
	}
	if err := b.boardCheckContentPolicy(u, body); err != nil {
		return err
	}
	return b.st.UpdatePost(post.ID, body, b.now())
}

// DeletePost soft deletes a post. Only area moderators may do this.
func (b *Boards) DeletePost(ctx context.Context, actor *domain.User, postID int64, reason string) error {
	post, thread, area, err := b.boardLoadPost(postID, actor)
	if err != nil {
		return err
	}
	if !boardCanModerate(area, actor) {
		return fmt.Errorf("%w: you cannot moderate %q", domain.ErrPermission, area.Tag)
	}
	reason = render.SanitizeLine(reason)
	if err := b.st.SoftDeletePost(post.ID, actor.ID, reason); err != nil {
		return err
	}
	return b.boardAudit(actor, "post.delete", "post", fmt.Sprintf("%d", post.ID), map[string]any{
		"thread": thread.ID,
		"area":   area.Tag,
		"reason": reason,
	})
}

// SetThreadFlags applies moderation flags to a thread and audits each change.
func (b *Boards) SetThreadFlags(ctx context.Context, actor *domain.User, threadID string, sticky, locked bool) error {
	thread, err := b.st.ThreadByID(threadID, "")
	if err != nil {
		return err
	}
	area, err := b.st.BoardAreaByID(thread.AreaID)
	if err != nil {
		return err
	}
	if !boardCanModerate(area, actor) {
		return fmt.Errorf("%w: you cannot moderate %q", domain.ErrPermission, area.Tag)
	}
	if thread.Deleted {
		return domain.ErrNotFound
	}
	if sticky == thread.Sticky && locked == thread.Locked {
		return nil
	}
	if err := b.st.SetThreadFlags(thread.ID, sticky, locked); err != nil {
		return err
	}
	if sticky != thread.Sticky {
		action := "thread.unsticky"
		if sticky {
			action = "thread.sticky"
		}
		if err := b.boardAudit(actor, action, "thread", thread.ID, map[string]any{
			"area": area.Tag, "sticky": sticky,
		}); err != nil {
			return err
		}
	}
	if locked != thread.Locked {
		action := "thread.unlock"
		if locked {
			action = "thread.lock"
		}
		if err := b.boardAudit(actor, action, "thread", thread.ID, map[string]any{
			"area": area.Tag, "locked": locked,
		}); err != nil {
			return err
		}
	}
	return nil
}

// MoveThread rehomes a thread. The actor must be able to moderate both the
// source and destination areas.
func (b *Boards) MoveThread(ctx context.Context, actor *domain.User, threadID, toAreaID string) error {
	thread, err := b.st.ThreadByID(threadID, "")
	if err != nil {
		return err
	}
	from, err := b.st.BoardAreaByID(thread.AreaID)
	if err != nil {
		return err
	}
	to, err := b.st.BoardAreaByID(toAreaID)
	if err != nil {
		return err
	}
	if !boardCanModerate(from, actor) || !boardCanModerate(to, actor) {
		return fmt.Errorf("%w: you cannot moderate both areas", domain.ErrPermission)
	}
	if from.ID == to.ID {
		return fmt.Errorf("%w: thread is already in %q", domain.ErrConflict, to.Tag)
	}
	if thread.Deleted {
		return domain.ErrNotFound
	}
	if err := b.st.MoveThread(thread.ID, to.ID); err != nil {
		return err
	}
	return b.boardAudit(actor, "thread.move", "thread", thread.ID, map[string]any{
		"from": from.Tag, "to": to.Tag,
	})
}

// boardThreadPageSize bounds how many posts a thread screen holds in memory.
const boardThreadPageSize = 50

// OlderPosts loads the page of posts before beforeID. Callers use it to walk
// backwards through long threads instead of loading everything at once.
func (b *Boards) OlderPosts(ctx context.Context, u *domain.User, threadID string, beforeID int64, limit int) ([]domain.Post, error) {
	thread, area, err := b.boardLoadThread(threadID, u)
	if err != nil {
		return nil, err
	}
	includeDeleted := boardCanModerate(area, u)
	return b.st.PostsByThreadPage(thread.ID, beforeID, limit, includeDeleted)
}

// MarkRead advances the user's read pointer for a thread to its latest live
// post. Guests are read-only and have no state, so this is a no-op for them.
func (b *Boards) MarkRead(ctx context.Context, u *domain.User, threadID string) error {
	if u == nil || u.ID == "" {
		return nil
	}
	thread, _, err := b.boardLoadThread(threadID, u)
	if err != nil {
		return err
	}
	last, err := b.st.MaxPostID(thread.ID)
	if err != nil {
		return err
	}
	return b.st.MarkThreadRead(u.ID, thread.ID, last, b.now())
}

// MarkAllRead marks every live thread in an area read.
func (b *Boards) MarkAllRead(ctx context.Context, u *domain.User, areaID string) error {
	if u == nil || u.ID == "" {
		return nil
	}
	area, err := b.st.BoardAreaByID(areaID)
	if err != nil {
		return err
	}
	if !boardCanRead(area, u) {
		return fmt.Errorf("%w: area %q is not readable", domain.ErrPermission, area.Tag)
	}
	return b.st.MarkAreaRead(u.ID, area.ID, b.now())
}

// UnreadTotal counts unread posts across every area the user can read.
func (b *Boards) UnreadTotal(ctx context.Context, userID string) (int, error) {
	if strings.TrimSpace(userID) == "" {
		return 0, nil
	}
	u, err := b.st.UserByID(userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return 0, nil
		}
		return 0, err
	}
	areas, err := b.Areas(ctx, u)
	if err != nil {
		return 0, err
	}
	ids := make([]string, 0, len(areas))
	for _, a := range areas {
		ids = append(ids, a.ID)
	}
	return b.st.UnreadTotalForAreas(u.ID, ids)
}

// UnreadByArea returns unread counts keyed by area ID for readable areas.
func (b *Boards) UnreadByArea(ctx context.Context, u *domain.User) (map[string]int, error) {
	areas, err := b.Areas(ctx, u)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(areas))
	for _, a := range areas {
		ids = append(ids, a.ID)
	}
	return b.st.UnreadCountsByArea(boardUserID(u), ids)
}

// Search runs full-text search over readable areas. areaID narrows results to
// one area (and is ACL checked).
func (b *Boards) Search(ctx context.Context, u *domain.User, query, areaID string, limit int) ([]domain.Post, error) {
	query = strings.TrimSpace(render.SanitizeLine(query))
	if query == "" {
		return nil, fmt.Errorf("%w: search query is empty", domain.ErrInvalid)
	}
	areas, err := b.Areas(ctx, u)
	if err != nil {
		return nil, err
	}
	var ids []string
	if strings.TrimSpace(areaID) != "" {
		found := false
		for _, a := range areas {
			if a.ID == areaID {
				ids = []string{a.ID}
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: area is not readable", domain.ErrPermission)
		}
	} else {
		for _, a := range areas {
			ids = append(ids, a.ID)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	return b.st.SearchPosts(query, ids, limit)
}
