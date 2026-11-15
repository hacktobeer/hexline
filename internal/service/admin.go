package service

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/render"
	"github.com/hacktobeer/hexline/internal/store"
)

// Admin implements privileged operations and the audit trail.
type Admin struct {
	st     *store.Store
	cfg    *config.Config
	broker *hub.Broker
}

// NewAdmin wires the admin service.
func NewAdmin(st *store.Store, cfg *config.Config, broker *hub.Broker) *Admin {
	return &Admin{st: st, cfg: cfg, broker: broker}
}

// Stats is the board-wide snapshot shown by the sysop menu and CLI.
type Stats struct {
	Users       int
	Active      int
	Probation   int
	Suspended   int
	Areas       int
	Threads     int
	Posts       int
	FileAreas   int
	Files       int
	Mail        int
	Oneliners   int
	Sessions24h int
	DBBytes     int64
}

// PruneResult reports how many rows each retention category removed (or would
// remove, in dry-run mode).
type PruneResult struct {
	Sessions     int64
	Audit        int64
	Oneliners    int64
	DeletedPosts int64
}

var adminAreaTagRe = regexp.MustCompile(`^[a-z0-9-]{2,24}$`)

// Stats gathers counters for the dashboard.
func (a *Admin) Stats(ctx context.Context) (*Stats, error) {
	c, err := a.st.AdminCounts()
	if err != nil {
		return nil, err
	}
	return &Stats{
		Users: c.Users, Active: c.Active, Probation: c.Probation, Suspended: c.Suspended,
		Areas: c.Areas, Threads: c.Threads, Posts: c.Posts,
		FileAreas: c.FileAreas, Files: c.Files, Mail: c.Mail, Oneliners: c.Oneliners,
		Sessions24h: c.Sessions24h, DBBytes: c.DBBytes,
	}, nil
}

// ListAudit returns recent audit entries, newest first.
func (a *Admin) ListAudit(ctx context.Context, limit int) ([]domain.AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	return a.st.ListAudit(limit)
}

// Broadcast publishes a notice to every session.
func (a *Admin) Broadcast(ctx context.Context, actor *domain.User, text string) error {
	if err := adminRequireSysop(actor); err != nil {
		return err
	}
	text = strings.TrimSpace(render.Sanitize(text))
	if text == "" {
		return fmt.Errorf("%w: broadcast text is required", domain.ErrInvalid)
	}
	if a.broker != nil {
		a.broker.Publish(hub.Event{
			Kind: hub.KindNotice, Scope: "*", FromID: actor.ID, From: actor.Handle, Text: text,
		})
	}
	return a.audit(actor, "admin.broadcast", "system", "broadcast",
		adminDetail(map[string]any{"text": text}))
}

// CreateArea provisions a message conference.
func (a *Admin) CreateArea(ctx context.Context, actor *domain.User,
	tag, name, description string, sortOrder int,
	aclRead, aclPost, aclModerate string) (*domain.Area, error) {
	if err := adminRequireSysop(actor); err != nil {
		return nil, err
	}
	tag, err := adminValidateTag(tag)
	if err != nil {
		return nil, err
	}
	name, description, err = adminValidateNameDesc(name, description)
	if err != nil {
		return nil, err
	}
	area := &domain.Area{
		Tag: tag, Name: name, Description: description, SortOrder: sortOrder,
		IsPublic: true,
	}
	if area.ACL.Read, err = adminACL("read", aclRead); err != nil {
		return nil, err
	}
	if area.ACL.Post, err = adminACL("post", aclPost); err != nil {
		return nil, err
	}
	if area.ACL.Moderate, err = adminACL("moderate", aclModerate); err != nil {
		return nil, err
	}
	if err := a.st.CreateArea(area); err != nil {
		return nil, err
	}
	if err := a.audit(actor, "area.create", "area", area.ID, adminDetail(map[string]any{
		"tag": area.Tag, "name": area.Name, "sort_order": area.SortOrder,
		"acl_read": domain.FormatACL(area.ACL.Read), "acl_post": domain.FormatACL(area.ACL.Post),
		"acl_moderate": domain.FormatACL(area.ACL.Moderate),
	})); err != nil {
		return nil, err
	}
	return area, nil
}

// UpdateArea edits an existing area. The tag is immutable.
func (a *Admin) UpdateArea(ctx context.Context, actor *domain.User, id, name, description string,
	sortOrder int, aclRead, aclPost, aclModerate string, retentionDays, rateLimitPerHour int) error {
	if err := adminRequireSysop(actor); err != nil {
		return err
	}
	if retentionDays < 0 {
		return fmt.Errorf("%w: retention days must be >= 0", domain.ErrInvalid)
	}
	if rateLimitPerHour < 0 {
		return fmt.Errorf("%w: rate limit must be >= 0", domain.ErrInvalid)
	}
	name, description, err := adminValidateNameDesc(name, description)
	if err != nil {
		return err
	}
	area, err := a.st.AdminAreaByID(id)
	if err != nil {
		return err
	}
	if area.ACL.Read, err = adminACL("read", aclRead); err != nil {
		return err
	}
	if area.ACL.Post, err = adminACL("post", aclPost); err != nil {
		return err
	}
	if area.ACL.Moderate, err = adminACL("moderate", aclModerate); err != nil {
		return err
	}
	area.Name = name
	area.Description = description
	area.SortOrder = sortOrder
	area.RetentionDays = retentionDays
	area.RateLimitPerHour = rateLimitPerHour
	if err := a.st.UpdateArea(area); err != nil {
		return err
	}
	return a.audit(actor, "area.update", "area", area.ID, adminDetail(map[string]any{
		"tag": area.Tag, "name": area.Name, "description": area.Description,
		"sort_order": area.SortOrder, "acl_read": domain.FormatACL(area.ACL.Read),
		"acl_post":       domain.FormatACL(area.ACL.Post),
		"acl_moderate":   domain.FormatACL(area.ACL.Moderate),
		"retention_days": area.RetentionDays, "rate_limit_per_hour": area.RateLimitPerHour,
	}))
}

// DeleteArea removes an area, refusing while threads exist unless force is set.
func (a *Admin) DeleteArea(ctx context.Context, actor *domain.User, id string, force bool) error {
	if err := adminRequireSysop(actor); err != nil {
		return err
	}
	area, err := a.st.AdminAreaByID(id)
	if err != nil {
		return err
	}
	if err := a.st.DeleteArea(id, force); err != nil {
		return err
	}
	return a.audit(actor, "area.delete", "area", id, adminDetail(map[string]any{
		"tag": area.Tag, "name": area.Name, "force": force,
	}))
}

// CreateFileArea provisions a download area.
func (a *Admin) CreateFileArea(ctx context.Context, actor *domain.User,
	tag, name, description string, sortOrder int,
	aclRead, aclUpload string, quotaBytes int64) (*domain.FileArea, error) {
	if err := adminRequireSysop(actor); err != nil {
		return nil, err
	}
	tag, err := adminValidateTag(tag)
	if err != nil {
		return nil, err
	}
	name, description, err = adminValidateNameDesc(name, description)
	if err != nil {
		return nil, err
	}
	if quotaBytes < 0 {
		return nil, fmt.Errorf("%w: quota must be >= 0", domain.ErrInvalid)
	}
	area := &domain.FileArea{
		Tag: tag, Name: name, Description: description, SortOrder: sortOrder,
		QuotaBytes: quotaBytes,
	}
	if area.ACL.Read, err = adminACL("read", aclRead); err != nil {
		return nil, err
	}
	if area.ACL.Post, err = adminACL("upload", aclUpload); err != nil {
		return nil, err
	}
	area.ACL.Moderate = []domain.Role{domain.RoleModerator}
	if err := a.st.CreateFileArea(area); err != nil {
		return nil, err
	}
	if err := a.audit(actor, "filearea.create", "filearea", area.ID, adminDetail(map[string]any{
		"tag": area.Tag, "name": area.Name, "sort_order": area.SortOrder,
		"acl_read": domain.FormatACL(area.ACL.Read), "acl_upload": domain.FormatACL(area.ACL.Post),
		"quota_bytes": area.QuotaBytes,
	})); err != nil {
		return nil, err
	}
	return area, nil
}

// SetBan records a handle or IP-hash ban. A zero expiry means permanent.
func (a *Admin) SetBan(ctx context.Context, actor *domain.User,
	scope, value, reason string, expiresAt time.Time) (*domain.Ban, error) {
	if err := adminRequireSysop(actor); err != nil {
		return nil, err
	}
	scope = strings.ToLower(strings.TrimSpace(scope))
	switch scope {
	case "handle", "ip":
	default:
		return nil, fmt.Errorf("%w: ban scope must be handle or ip", domain.ErrInvalid)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("%w: ban value is required", domain.ErrInvalid)
	}
	switch scope {
	case "handle":
		// Bans must be storable and comparable; the account need not exist yet.
		if err := domain.ValidateHandleShape(value); err != nil {
			return nil, err
		}
	case "ip":
		// IP bans compare against the HMAC the server logs, never a raw address.
		if !adminValidIPHash(value) {
			return nil, fmt.Errorf("%w: ip bans need the 22-character ip_hash from the audit log, not a raw address", domain.ErrInvalid)
		}
	}
	b := &domain.Ban{
		Scope: scope, Value: value, Reason: render.SanitizeLine(reason),
		CreatedBy: actor.Handle, CreatedAt: time.Now().UTC(),
	}
	if !expiresAt.IsZero() {
		b.ExpiresAt = expiresAt.UTC()
	}
	if err := a.st.CreateBan(b); err != nil {
		return nil, err
	}
	if err := a.audit(actor, "ban.add", "ban", b.ID, adminDetail(map[string]any{
		"scope": b.Scope, "value": b.Value, "reason": b.Reason,
		"expires_at": b.ExpiresAt.Format(time.RFC3339),
	})); err != nil {
		return nil, err
	}
	return b, nil
}

// RemoveBan lifts a ban.
// adminValidIPHash matches the base64url HMAC the transport produces.
func adminValidIPHash(v string) bool {
	if len(v) != 22 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func (a *Admin) RemoveBan(ctx context.Context, actor *domain.User, id string) error {
	if err := adminRequireSysop(actor); err != nil {
		return err
	}
	if err := a.st.RemoveBan(id); err != nil {
		return err
	}
	return a.audit(actor, "ban.remove", "ban", id, "{}")
}

// ListBans returns every ban, including expired ones.
func (a *Admin) ListBans(ctx context.Context) ([]domain.Ban, error) {
	return a.st.ListBans()
}

// IsBanned reports whether handle or IP hash is banned right now. It is cheap,
// side-effect free and safe to call from the authentication path.
func (a *Admin) IsBanned(ctx context.Context, handle, ipHash string) (bool, string, error) {
	now := time.Now().UTC()
	if handle != "" {
		b, err := a.st.ActiveBan("handle", strings.TrimSpace(handle), now)
		if err == nil {
			return true, b.Reason, nil
		}
		if err != domain.ErrNotFound {
			return false, "", err
		}
	}
	if ipHash != "" {
		b, err := a.st.ActiveBan("ip", ipHash, now)
		if err == nil {
			return true, b.Reason, nil
		}
		if err != domain.ErrNotFound {
			return false, "", err
		}
	}
	return false, "", nil
}

// Prune applies configured retention. A dry run reports counts without
// deleting. Categories with a zero retention window are left alone.
func (a *Admin) Prune(ctx context.Context, dryRun bool) (PruneResult, error) {
	var res PruneResult
	actor, hasActor := adminActorFromContext(ctx)
	if hasActor {
		if err := adminRequireSysop(actor); err != nil {
			return res, err
		}
	}
	now := time.Now().UTC()
	ret := a.cfg.Retention
	if ret.SessionsDays > 0 {
		cutoff := now.Add(-time.Duration(ret.SessionsDays) * 24 * time.Hour)
		var err error
		if dryRun {
			res.Sessions, err = a.st.CountSessionsBefore(cutoff)
		} else {
			res.Sessions, err = a.st.PruneSessions(cutoff)
			if err == nil {
				// Login throttle rows have no separate knob; follow sessions.
				_, err = a.st.PruneLoginAttempts(cutoff)
			}
		}
		if err != nil {
			return res, err
		}
	}
	if ret.AuditDays > 0 {
		cutoff := now.Add(-time.Duration(ret.AuditDays) * 24 * time.Hour)
		var err error
		if dryRun {
			res.Audit, err = a.st.CountAuditBefore(cutoff)
		} else {
			res.Audit, err = a.st.PruneAudit(cutoff)
		}
		if err != nil {
			return res, err
		}
	}
	if ret.OnelinerDays > 0 {
		cutoff := now.Add(-time.Duration(ret.OnelinerDays) * 24 * time.Hour)
		var err error
		if dryRun {
			res.Oneliners, err = a.st.CountOnelinersBefore(cutoff)
		} else {
			res.Oneliners, err = a.st.PruneOneliners(cutoff)
		}
		if err != nil {
			return res, err
		}
	}
	if ret.DeletedPostsDays > 0 {
		cutoff := now.Add(-time.Duration(ret.DeletedPostsDays) * 24 * time.Hour)
		var err error
		if dryRun {
			res.DeletedPosts, err = a.st.CountDeletedPostsBefore(cutoff)
		} else {
			res.DeletedPosts, err = a.st.PruneDeletedPosts(cutoff)
		}
		if err != nil {
			return res, err
		}
	}
	if !dryRun {
		if err := a.audit(actor, "admin.prune", "system", "retention", adminDetail(map[string]any{
			"sessions": res.Sessions, "audit": res.Audit,
			"oneliners": res.Oneliners, "deleted_posts": res.DeletedPosts,
		})); err != nil {
			return res, err
		}
	}
	return res, nil
}

// SetUserStatus changes an account lifecycle state.
func (a *Admin) SetUserStatus(ctx context.Context, actor *domain.User, userID string, status domain.Status) error {
	if err := adminRequireSysop(actor); err != nil {
		return err
	}
	switch status {
	case domain.StatusActive, domain.StatusProbation, domain.StatusSuspended, domain.StatusDeleted:
	default:
		return fmt.Errorf("%w: unknown account status %q", domain.ErrInvalid, status)
	}
	u, err := a.st.UserByID(userID)
	if err != nil {
		return err
	}
	if err := a.st.SetStatus(userID, status); err != nil {
		return err
	}
	return a.audit(actor, "user.status", "user", userID, adminDetail(map[string]any{
		"handle": u.Handle, "status": status,
	}))
}

// SetUserRole changes an account role. Sysop only.
func (a *Admin) SetUserRole(ctx context.Context, actor *domain.User, userID string, role domain.Role) error {
	if err := adminRequireSysop(actor); err != nil {
		return err
	}
	if !role.Valid() {
		return fmt.Errorf("%w: unknown role %q", domain.ErrInvalid, role)
	}
	u, err := a.st.UserByID(userID)
	if err != nil {
		return err
	}
	if err := a.st.SetRole(userID, role); err != nil {
		return err
	}
	return a.audit(actor, "user.role", "user", userID, adminDetail(map[string]any{
		"handle": u.Handle, "role": role,
	}))
}

// --- bulletins & polls ---

// ListBulletins returns sysop bulletins in display order.
func (a *Admin) ListBulletins(ctx context.Context) ([]domain.Bulletin, error) {
	return a.st.AdminListBulletins()
}

// CreateBulletin publishes a sysop notice.
func (a *Admin) CreateBulletin(ctx context.Context, actor *domain.User, title, body string, sortOrder int) (*domain.Bulletin, error) {
	if err := adminRequireSysop(actor); err != nil {
		return nil, err
	}
	title = strings.TrimSpace(render.SanitizeLine(title))
	if title == "" {
		return nil, fmt.Errorf("%w: bulletin title is required", domain.ErrInvalid)
	}
	body = strings.TrimSpace(render.Sanitize(body))
	if body == "" {
		return nil, fmt.Errorf("%w: bulletin body is required", domain.ErrInvalid)
	}
	b := &domain.Bulletin{Title: title, Body: body, Sort: sortOrder, Active: true}
	if err := a.st.AdminCreateBulletin(b); err != nil {
		return nil, err
	}
	if err := a.audit(actor, "bulletin.create", "bulletin", b.ID, adminDetail(map[string]any{
		"title": b.Title, "sort": b.Sort,
	})); err != nil {
		return nil, err
	}
	return b, nil
}

// DeleteBulletin removes a bulletin.
func (a *Admin) DeleteBulletin(ctx context.Context, actor *domain.User, id string) error {
	if err := adminRequireSysop(actor); err != nil {
		return err
	}
	if err := a.st.AdminDeleteBulletin(id); err != nil {
		return err
	}
	return a.audit(actor, "bulletin.delete", "bulletin", id, "{}")
}

// CreatePoll publishes a single-choice poll.
func (a *Admin) CreatePoll(ctx context.Context, actor *domain.User, question string, options []string, closesAt time.Time) (*domain.Poll, error) {
	if err := adminRequireSysop(actor); err != nil {
		return nil, err
	}
	question = strings.TrimSpace(render.SanitizeLine(question))
	if question == "" {
		return nil, fmt.Errorf("%w: poll question is required", domain.ErrInvalid)
	}
	var opts []domain.PollOption
	seen := map[string]bool{}
	for _, raw := range options {
		label := strings.TrimSpace(render.SanitizeLine(raw))
		if label == "" {
			continue
		}
		key := strings.ToLower(label)
		if seen[key] {
			return nil, fmt.Errorf("%w: duplicate poll option %q", domain.ErrConflict, label)
		}
		seen[key] = true
		opts = append(opts, domain.PollOption{Label: label, Sort: len(opts) + 1})
	}
	if len(opts) < 2 {
		return nil, fmt.Errorf("%w: a poll needs at least two options", domain.ErrInvalid)
	}
	p := &domain.Poll{Question: question, CreatedBy: actor.ID, CreatedAt: time.Now().UTC(), Options: opts}
	if !closesAt.IsZero() {
		p.ClosesAt = closesAt.UTC()
	}
	if err := a.st.AdminCreatePoll(p); err != nil {
		return nil, err
	}
	if err := a.audit(actor, "poll.create", "poll", p.ID, adminDetail(map[string]any{
		"question": p.Question, "options": len(opts), "closes_at": p.ClosesAt.Format(time.RFC3339),
	})); err != nil {
		return nil, err
	}
	return p, nil
}

// --- helpers ---

func adminRequireSysop(actor *domain.User) error {
	if actor == nil || !actor.Role.AtLeast(domain.RoleSysop) {
		return domain.ErrPermission
	}
	return nil
}

// adminActorKey is the context key used by the CLI so Prune keeps its exact
// required signature while still auditing the actor.
type adminActorKey struct{}

// WithAdminActor attaches the acting account for methods whose required
// signature has no actor parameter.
func WithAdminActor(ctx context.Context, actor *domain.User) context.Context {
	return context.WithValue(ctx, adminActorKey{}, actor)
}

func adminActorFromContext(ctx context.Context) (*domain.User, bool) {
	v := ctx.Value(adminActorKey{})
	if v == nil {
		return nil, false
	}
	u, ok := v.(*domain.User)
	return u, ok
}

func adminValidateTag(tag string) (string, error) {
	tag = strings.TrimSpace(tag)
	if !adminAreaTagRe.MatchString(tag) {
		return "", fmt.Errorf("%w: tag must be 2-24 lowercase letters, digits or dashes", domain.ErrInvalid)
	}
	return tag, nil
}

func adminValidateNameDesc(name, description string) (string, string, error) {
	name = strings.TrimSpace(render.SanitizeLine(name))
	if name == "" {
		return "", "", fmt.Errorf("%w: name is required", domain.ErrInvalid)
	}
	if len(name) > 80 {
		return "", "", fmt.Errorf("%w: name must be at most 80 characters", domain.ErrInvalid)
	}
	description = strings.TrimSpace(render.SanitizeLine(description))
	if len(description) > 500 {
		return "", "", fmt.Errorf("%w: description must be at most 500 characters", domain.ErrInvalid)
	}
	return name, description, nil
}

func adminACL(label, raw string) ([]domain.Role, error) {
	roles, err := domain.ParseACL(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s ACL: %v", domain.ErrInvalid, label, err)
	}
	return roles, nil
}

func adminDetail(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func (a *Admin) audit(actor *domain.User, action, kind, target, detail string) error {
	e := domain.AuditEntry{
		Action: action, TargetKind: kind, TargetID: target, Detail: detail,
	}
	if actor != nil {
		e.ActorID, e.Actor = actor.ID, actor.Handle
	} else {
		e.Actor = "system"
	}
	return a.st.RecordAudit(e)
}
