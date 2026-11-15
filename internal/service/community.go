package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/render"
	"github.com/hacktobeer/hexline/internal/store"
)

const (
	commOnelinerMax      = 200
	commOnelinerPerBurst = 5
	commOnelinerWindow   = 10 * time.Minute
	commChatMax          = 400
	commChatHistoryMax   = 100
	commPollQuestionMax  = 160
	commPollOptionMax    = 80
	commPollMinOptions   = 2
	commPollMaxOptions   = 10
	commBulletinTitleMax = 160

	commChannelGlobal = "global"
	commChannelSysop  = "sysop"
)

// Community implements oneliners, polls, bulletins, chat history and presence.
type Community struct {
	st     *store.Store
	cfg    *config.Config
	broker *hub.Broker

	now func() time.Time

	mu          sync.Mutex
	onelinerWin map[string]*commWindow
	chatBuckets map[string]*commBucket
	chatLast    map[string]time.Time
	chatHistory map[string][]hub.Event
}

type commWindow struct {
	start time.Time
	count int
}

type commBucket struct {
	tokens float64
	last   time.Time
}

// NewCommunity wires the community service.
func NewCommunity(st *store.Store, cfg *config.Config, broker *hub.Broker) *Community {
	return &Community{
		st:          st,
		cfg:         cfg,
		broker:      broker,
		now:         func() time.Time { return time.Now().UTC() },
		onelinerWin: map[string]*commWindow{},
		chatBuckets: map[string]*commBucket{},
		chatLast:    map[string]time.Time{},
		chatHistory: map[string][]hub.Event{},
	}
}

// SetClock replaces the service clock (tests use a fake clock for rate limits).
func (c *Community) SetClock(fn func() time.Time) {
	if fn == nil {
		fn = func() time.Time { return time.Now().UTC() }
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = fn
	// Existing windows were measured against the previous clock; reset them so
	// tests can jump in either direction without stale state.
	c.onelinerWin = map[string]*commWindow{}
	c.chatBuckets = map[string]*commBucket{}
}

func (c *Community) clock() time.Time { return c.now() }

// --- one-liners ---

// Oneliners returns the newest one-liners. Hidden entries are included and
// flagged; the caller decides whether the actor may see them.
func (c *Community) Oneliners(ctx context.Context, limit int) ([]domain.Oneliner, error) {
	return c.st.ListOneliners(limit)
}

// PostOneliner sanitizes, validates and stores a one-liner. A user may post at
// most five per ten minutes.
func (c *Community) PostOneliner(ctx context.Context, u *domain.User, body string) (*domain.Oneliner, error) {
	if err := commRequireWrite(u); err != nil {
		return nil, err
	}
	body = render.SanitizeLine(body)
	if body == "" {
		return nil, fmt.Errorf("%w: one-liner is empty", domain.ErrInvalid)
	}
	if utf8.RuneCountInString(body) > commOnelinerMax {
		return nil, fmt.Errorf("%w: one-liners are limited to %d characters", domain.ErrInvalid, commOnelinerMax)
	}
	if err := c.consumeOneliner(u.ID); err != nil {
		return nil, err
	}
	o := &domain.Oneliner{AuthorID: u.ID, Author: u.Handle, Body: body, CreatedAt: c.clock()}
	if err := c.st.CreateOneliner(o); err != nil {
		return nil, err
	}
	return o, nil
}

// HideOneliner hides or restores a one-liner. Moderators only; audited.
func (c *Community) HideOneliner(ctx context.Context, actor *domain.User, id int64, hide bool) error {
	if err := commRequireMod(actor); err != nil {
		return err
	}
	if id <= 0 {
		return fmt.Errorf("%w: unknown one-liner", domain.ErrInvalid)
	}
	if err := c.st.SetOnelinerHidden(id, hide, actor.ID); err != nil {
		return err
	}
	action := "oneliner.hide"
	if !hide {
		action = "oneliner.show"
	}
	return c.audit(actor, action, "oneliner", strconv.FormatInt(id, 10), map[string]any{"hidden": hide})
}

func (c *Community) consumeOneliner(userID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	w := c.onelinerWin[userID]
	if w == nil || now.Sub(w.start) >= commOnelinerWindow {
		c.onelinerWin[userID] = &commWindow{start: now, count: 1}
		return nil
	}
	if w.count >= commOnelinerPerBurst {
		return fmt.Errorf("%w: one-liners are limited to %d per %s",
			domain.ErrRateLimited, commOnelinerPerBurst, commOnelinerWindow)
	}
	w.count++
	return nil
}

// --- polls ---

// Polls returns all polls (hidden ones only for moderators) with vote counts
// and the caller's own vote.
func (c *Community) Polls(ctx context.Context, u *domain.User) ([]domain.Poll, error) {
	userID := ""
	if u != nil {
		userID = u.ID
	}
	polls, err := c.st.ListPolls(userID)
	if err != nil {
		return nil, err
	}
	if u != nil && u.Role.AtLeast(domain.RoleModerator) {
		return polls, nil
	}
	visible := polls[:0]
	for _, p := range polls {
		if !p.Hidden {
			visible = append(visible, p)
		}
	}
	return visible, nil
}

// Poll loads one poll with results and the caller's vote.
func (c *Community) Poll(ctx context.Context, u *domain.User, id string) (*domain.Poll, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: missing poll id", domain.ErrInvalid)
	}
	userID := ""
	if u != nil {
		userID = u.ID
	}
	p, err := c.st.PollByID(id, userID)
	if err != nil {
		return nil, err
	}
	if p.Hidden && (u == nil || !u.Role.AtLeast(domain.RoleModerator)) {
		return nil, domain.ErrNotFound
	}
	return p, nil
}

// CreatePoll creates a poll. Moderators and sysops only; audited.
func (c *Community) CreatePoll(ctx context.Context, actor *domain.User, question string, options []string,
	closesAt time.Time) (*domain.Poll, error) {
	if err := commRequireMod(actor); err != nil {
		return nil, err
	}
	question = render.SanitizeLine(question)
	if question == "" {
		return nil, fmt.Errorf("%w: poll question is required", domain.ErrInvalid)
	}
	if utf8.RuneCountInString(question) > commPollQuestionMax {
		return nil, fmt.Errorf("%w: poll question is limited to %d characters", domain.ErrInvalid, commPollQuestionMax)
	}
	if len(options) < commPollMinOptions || len(options) > commPollMaxOptions {
		return nil, fmt.Errorf("%w: a poll needs %d to %d options", domain.ErrInvalid,
			commPollMinOptions, commPollMaxOptions)
	}
	labels := make([]string, 0, len(options))
	for _, raw := range options {
		label := render.SanitizeLine(raw)
		if label == "" {
			return nil, fmt.Errorf("%w: poll options must not be empty", domain.ErrInvalid)
		}
		if utf8.RuneCountInString(label) > commPollOptionMax {
			return nil, fmt.Errorf("%w: poll options are limited to %d characters", domain.ErrInvalid, commPollOptionMax)
		}
		labels = append(labels, label)
	}
	now := c.clock()
	if !closesAt.IsZero() {
		closesAt = closesAt.UTC()
		if !closesAt.After(now) {
			return nil, fmt.Errorf("%w: the close time must be in the future", domain.ErrInvalid)
		}
	}
	p := &domain.Poll{
		Question:  question,
		CreatedBy: actor.ID,
		CreatedAt: now,
		ClosesAt:  closesAt,
	}
	if err := c.st.CreatePoll(p, labels); err != nil {
		return nil, err
	}
	if err := c.audit(actor, "poll.create", "poll", p.ID, map[string]any{
		"question": question, "options": len(labels),
	}); err != nil {
		return nil, err
	}
	return p, nil
}

// Vote records the caller's single vote while the poll is open. The composite
// primary key rejects a second vote with ErrConflict.
func (c *Community) Vote(ctx context.Context, u *domain.User, pollID string, optionID int64) error {
	if err := commRequireWrite(u); err != nil {
		return err
	}
	p, err := c.st.PollByID(strings.TrimSpace(pollID), "")
	if err != nil {
		return err
	}
	if p.Hidden && !u.Role.AtLeast(domain.RoleModerator) {
		return domain.ErrNotFound
	}
	if !commPollOpen(*p, c.clock()) {
		return fmt.Errorf("%w: this poll is closed", domain.ErrConflict)
	}
	found := false
	for _, o := range p.Options {
		if o.ID == optionID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: unknown poll option", domain.ErrInvalid)
	}
	return c.st.Vote(p.ID, optionID, u.ID, c.clock())
}

func commPollOpen(p domain.Poll, now time.Time) bool {
	return p.ClosesAt.IsZero() || now.Before(p.ClosesAt)
}

// --- bulletins ---

// Bulletins returns active bulletins the caller has not dismissed. Guests see
// all active bulletins because they have no persistent dismissals.
func (c *Community) Bulletins(ctx context.Context, u *domain.User) ([]domain.Bulletin, error) {
	if u != nil && u.ID != "" {
		return c.st.ActiveBulletinsFor(u.ID)
	}
	return c.st.ListBulletins(true)
}

// CreateBulletin creates a bulletin. Moderators and sysops only; audited.
func (c *Community) CreateBulletin(ctx context.Context, actor *domain.User, title, body string,
	sort int) (*domain.Bulletin, error) {
	if err := commRequireMod(actor); err != nil {
		return nil, err
	}
	title, body, err := c.commValidateBulletin(title, body)
	if err != nil {
		return nil, err
	}
	now := c.clock()
	b := &domain.Bulletin{
		Title: title, Body: body, Sort: sort, Active: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := c.st.CreateBulletin(b); err != nil {
		return nil, err
	}
	if err := c.audit(actor, "bulletin.create", "bulletin", b.ID, map[string]any{
		"title": title, "sort": sort, "active": true,
	}); err != nil {
		return nil, err
	}
	return b, nil
}

// UpdateBulletin replaces a bulletin's title, body and active flag.
func (c *Community) UpdateBulletin(ctx context.Context, actor *domain.User, id, title, body string,
	active bool) error {
	if err := commRequireMod(actor); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: missing bulletin id", domain.ErrInvalid)
	}
	title, body, err := c.commValidateBulletin(title, body)
	if err != nil {
		return err
	}
	if err := c.st.UpdateBulletin(id, title, body, active, c.clock()); err != nil {
		return err
	}
	return c.audit(actor, "bulletin.update", "bulletin", id, map[string]any{
		"title": title, "active": active,
	})
}

// DeleteBulletin removes a bulletin. Moderators and sysops only; audited.
func (c *Community) DeleteBulletin(ctx context.Context, actor *domain.User, id string) error {
	if err := commRequireMod(actor); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: missing bulletin id", domain.ErrInvalid)
	}
	if err := c.st.DeleteBulletin(id); err != nil {
		return err
	}
	return c.audit(actor, "bulletin.delete", "bulletin", id, nil)
}

// Dismiss records a per-user "don't show again". It is idempotent.
func (c *Community) Dismiss(ctx context.Context, u *domain.User, bulletinID string) error {
	if u == nil || u.ID == "" || u.IsGuest {
		return domain.ErrPermission
	}
	bulletinID = strings.TrimSpace(bulletinID)
	if bulletinID == "" {
		return fmt.Errorf("%w: missing bulletin id", domain.ErrInvalid)
	}
	return c.st.DismissBulletin(u.ID, bulletinID)
}

func (c *Community) commValidateBulletin(title, body string) (string, string, error) {
	title = render.SanitizeLine(title)
	if title == "" {
		return "", "", fmt.Errorf("%w: bulletin title is required", domain.ErrInvalid)
	}
	if utf8.RuneCountInString(title) > commBulletinTitleMax {
		return "", "", fmt.Errorf("%w: bulletin titles are limited to %d characters",
			domain.ErrInvalid, commBulletinTitleMax)
	}
	body = render.Sanitize(body)
	maxBytes, maxLines := 32<<10, 1000
	if c.cfg != nil {
		maxBytes = c.cfg.Limits.PostMaxBytes
		maxLines = c.cfg.Limits.MaxBodyLines
	}
	if err := domain.ValidateBody(body, maxBytes, maxLines); err != nil {
		return "", "", err
	}
	return title, body, nil
}

// --- chat ---

// ChatSend publishes a chat message to the global or sysop channel and appends
// it to the in-memory scrollback. Guests may read but never send; the sysop
// channel is moderator-only.
func (c *Community) ChatSend(ctx context.Context, u *domain.User, channel, text string) error {
	ch, err := commChannel(channel)
	if err != nil {
		return err
	}
	if err := commRequireWrite(u); err != nil {
		return err
	}
	if ch == commChannelSysop && !u.Role.AtLeast(domain.RoleModerator) {
		return fmt.Errorf("%w: the sysop channel is for moderators", domain.ErrPermission)
	}
	text = render.SanitizeLine(text)
	if text == "" {
		return fmt.Errorf("%w: chat message is empty", domain.ErrInvalid)
	}
	if utf8.RuneCountInString(text) > commChatMax {
		return fmt.Errorf("%w: chat messages are limited to %d characters", domain.ErrInvalid, commChatMax)
	}
	now := c.clock()
	if err := c.consumeChat(u.ID, now); err != nil {
		return err
	}
	ev := hub.Event{
		Kind: hub.KindChat, Scope: "chat:" + ch,
		FromID: u.ID, From: u.Handle, Text: text, At: now,
	}
	c.mu.Lock()
	c.chatLast[u.ID] = now
	history := append(c.chatHistory[ch], ev)
	if len(history) > commChatHistoryMax {
		history = history[len(history)-commChatHistoryMax:]
	}
	c.chatHistory[ch] = history
	c.mu.Unlock()

	if c.broker != nil {
		c.broker.Publish(ev)
	}
	return nil
}

// ChatHistory returns a copy of the in-memory scrollback for a channel
// (newest last). Chat is never persisted.
func (c *Community) ChatHistory(channel string) []hub.Event {
	ch, err := commChannel(channel)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	src := c.chatHistory[ch]
	out := make([]hub.Event, len(src))
	copy(out, src)
	return out
}

// ChatLastSend reports when the user last sent a chat message.
func (c *Community) ChatLastSend(userID string) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.chatLast[userID]
}

func (c *Community) consumeChat(userID string, now time.Time) error {
	rate := 0
	if c.cfg != nil {
		rate = c.cfg.Limits.ChatRatePerMinute
	}
	if rate <= 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.chatBuckets[userID]
	if b == nil {
		b = &commBucket{tokens: float64(rate), last: now}
		c.chatBuckets[userID] = b
	}
	if now.After(b.last) {
		b.tokens += now.Sub(b.last).Seconds() * float64(rate) / 60
		if b.tokens > float64(rate) {
			b.tokens = float64(rate)
		}
	}
	b.last = now
	if b.tokens < 1 {
		return fmt.Errorf("%w: chat is limited to %d messages per minute", domain.ErrRateLimited, rate)
	}
	b.tokens--
	return nil
}

func commChannel(channel string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(channel)) {
	case "", commChannelGlobal:
		return commChannelGlobal, nil
	case commChannelSysop:
		return commChannelSysop, nil
	default:
		return "", fmt.Errorf("%w: unknown chat channel %q", domain.ErrInvalid, channel)
	}
}

// --- shared helpers ---

func commRequireWrite(u *domain.User) error {
	if u == nil || !u.CanWrite() {
		return domain.ErrPermission
	}
	return nil
}

func commRequireMod(u *domain.User) error {
	if u == nil || !u.Role.AtLeast(domain.RoleModerator) {
		return domain.ErrPermission
	}
	return nil
}

func (c *Community) audit(actor *domain.User, action, kind, id string, detail any) error {
	entry := domain.AuditEntry{Action: action, TargetKind: kind, TargetID: id}
	if actor != nil {
		entry.ActorID, entry.Actor = actor.ID, actor.Handle
	}
	if detail != nil {
		raw, err := json.Marshal(detail)
		if err != nil {
			return fmt.Errorf("service: audit detail: %w", err)
		}
		entry.Detail = string(raw)
	}
	return c.st.RecordAudit(entry)
}
