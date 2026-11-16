// Package service holds hexline's business logic. Screens and the admin CLI
// both call these types; no service touches terminal types or SQL strings.
package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/render"
	"github.com/hacktobeer/hexline/internal/store"
)

// Auth handles registration, login, profiles and probation (D3/D9).
type Auth struct {
	store  *store.Store
	cfg    *config.Config
	hasher *PasswordHasher
	now    func() time.Time
	mu     sync.Mutex
	fails  map[string]*failWindow
	audit  func(domain.AuditEntry)
	// bans is installed by the runtime; nil means no ban checking.
	bans func(ctx context.Context, handle, ipHash string) (bool, string, error)
}

// SetBanChecker installs the ban lookup used by login and registration.
func (a *Auth) SetBanChecker(fn func(ctx context.Context, handle, ipHash string) (bool, string, error)) {
	a.bans = fn
}

type failWindow struct {
	count int
	until time.Time
}

// NewAuth wires the auth service. audit may be nil.
func NewAuth(st *store.Store, cfg *config.Config, audit func(domain.AuditEntry)) *Auth {
	return &Auth{
		store:  st,
		cfg:    cfg,
		hasher: NewPasswordHasher(DefaultPasswordParams(), 4),
		now:    func() time.Time { return time.Now().UTC() },
		fails:  map[string]*failWindow{},
		audit:  audit,
	}
}

// SetClock replaces the clock (tests).
func (a *Auth) SetClock(fn func() time.Time) { a.now = fn }

// SetPasswordParams replaces the cost profile and hash concurrency. Call it
// once at boot, before serving.
func (a *Auth) SetPasswordParams(p PasswordParams, concurrency int) {
	if p.KeyLen == 0 {
		p.KeyLen = 32
	}
	a.hasher = NewPasswordHasher(p, concurrency)
}

// Hasher exposes the password hasher (admin CLI uses it).
func (a *Auth) Hasher() *PasswordHasher { return a.hasher }

// RegisterRequest is the input for account creation.
type RegisterRequest struct {
	Handle      string
	Password    string
	Email       string
	RealName    string
	Location    string
	Timezone    string
	IPHash      string
	AllowClosed bool // sysop override: bypass registration.open
	// AllowReserved lets the sysop CLI create handles like "sysop".
	AllowReserved bool
}

// Authenticate verifies credentials. Unknown handles return domain.ErrNotFound
// so the transport can offer registration; bad passwords return ErrPermission.
func (a *Auth) Authenticate(ctx context.Context, handle, password, ipHash string) (*domain.User, error) {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return nil, fmt.Errorf("%w: handle is required", domain.ErrInvalid)
	}
	if err := a.throttleCheck(handle, ipHash); err != nil {
		return nil, err
	}
	if err := a.checkBans(ctx, handle, ipHash); err != nil {
		return nil, err
	}
	u, err := a.store.UserByHandle(handle)
	if err != nil {
		// Burn the same argon2 cost as a real verify so the response time and
		// SSH outcome do not reveal whether the handle exists.
		a.hasher.Dummy()
		a.recordFailure(handle, ipHash, false)
		return nil, err
	}
	if u.Status == domain.StatusSuspended || u.Status == domain.StatusDeleted {
		a.recordFailure(handle, ipHash, false)
		return nil, domain.ErrSuspended
	}
	ok, rehash, err := a.hasher.Verify(password, u.PassHash)
	if err != nil {
		return nil, fmt.Errorf("%w: credentials could not be verified", domain.ErrUnavailable)
	}
	if !ok {
		a.recordFailure(handle, ipHash, false)
		return nil, fmt.Errorf("%w: invalid handle or password", domain.ErrPermission)
	}
	if rehash {
		if hash, err := a.hasher.Hash(password); err == nil {
			_ = a.store.SetPassword(u.ID, hash, EncodeParams(a.hasher.Params()))
		}
	}
	a.recordFailure(handle, ipHash, true)
	a.auditEvent(domain.AuditEntry{
		ActorID: u.ID, Actor: u.Handle, Action: "auth.login", TargetKind: "user",
		TargetID: u.ID, IPHash: ipHash,
	})
	return u, nil
}

// Register creates a probationary account (D3).
func (a *Auth) Register(ctx context.Context, req RegisterRequest) (*domain.User, error) {
	if !a.cfg.Registration.Open && !req.AllowClosed {
		return nil, fmt.Errorf("%w: registration is closed", domain.ErrPermission)
	}
	if err := a.checkBans(ctx, req.Handle, req.IPHash); err != nil {
		return nil, err
	}
	if req.AllowReserved {
		if err := domain.ValidateHandleShape(req.Handle); err != nil {
			return nil, err
		}
	} else if err := domain.ValidateHandle(req.Handle); err != nil {
		return nil, err
	}
	if err := domain.ValidatePassword(req.Password); err != nil {
		return nil, err
	}
	hash, err := a.hasher.Hash(req.Password)
	if err != nil {
		return nil, err
	}
	tz := req.Timezone
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return nil, fmt.Errorf("%w: unknown timezone %q", domain.ErrInvalid, tz)
	}
	u := &domain.User{
		Handle:     strings.TrimSpace(req.Handle),
		Email:      render.SanitizeLine(req.Email),
		RealName:   render.SanitizeLine(req.RealName),
		Location:   render.SanitizeLine(req.Location),
		Timezone:   tz,
		Role:       domain.RoleUser,
		Status:     domain.StatusProbation,
		CreatedAt:  a.now(),
		PassHash:   hash,
		PassParams: EncodeParams(a.hasher.Params()),
		Prefs:      domain.DefaultPrefs(),
	}
	if err := a.store.CreateUser(u); err != nil {
		return nil, err
	}
	a.auditEvent(domain.AuditEntry{
		ActorID: u.ID, Actor: u.Handle, Action: "auth.register", TargetKind: "user",
		TargetID: u.ID, IPHash: req.IPHash,
		Detail: `{"status":"probation"}`,
	})
	return u, nil
}

// KnownHandle reports whether a handle is registered.
func (a *Auth) KnownHandle(handle string) (bool, error) {
	return a.store.HandleExists(handle)
}

// ChangePassword verifies old and stores a fresh hash.
func (a *Auth) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	u, err := a.store.UserByID(userID)
	if err != nil {
		return err
	}
	ok, _, err := a.hasher.Verify(oldPassword, u.PassHash)
	if err != nil || !ok {
		return fmt.Errorf("%w: current password is incorrect", domain.ErrPermission)
	}
	if err := domain.ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := a.hasher.Hash(newPassword)
	if err != nil {
		return err
	}
	if err := a.store.SetPassword(u.ID, hash, EncodeParams(a.hasher.Params())); err != nil {
		return err
	}
	a.auditEvent(domain.AuditEntry{
		ActorID: u.ID, Actor: u.Handle, Action: "auth.password_change",
		TargetKind: "user", TargetID: u.ID,
	})
	return nil
}

// ResetPassword is the sysop path (CLI).
func (a *Auth) ResetPassword(ctx context.Context, handle, newPassword string) error {
	if err := domain.ValidatePassword(newPassword); err != nil {
		return err
	}
	u, err := a.store.UserByHandle(handle)
	if err != nil {
		return err
	}
	hash, err := a.hasher.Hash(newPassword)
	if err != nil {
		return err
	}
	if err := a.store.SetPassword(u.ID, hash, EncodeParams(a.hasher.Params())); err != nil {
		return err
	}
	a.auditEvent(domain.AuditEntry{
		Actor: "cli", Action: "auth.password_reset", TargetKind: "user", TargetID: u.ID,
		Detail: `{"handle":"` + u.Handle + `"}`,
	})
	return nil
}

// UpdateProfile saves profile fields for u.
func (a *Auth) UpdateProfile(ctx context.Context, u *domain.User) error {
	u.RealName = render.SanitizeLine(u.RealName)
	u.Location = render.SanitizeLine(u.Location)
	u.Email = render.SanitizeLine(u.Email)
	u.Signature = trimSignature(render.Sanitize(u.Signature), a.cfg.Limits.MaxSignatureLines)
	if _, err := time.LoadLocation(u.Timezone); err != nil {
		return fmt.Errorf("%w: unknown timezone %q", domain.ErrInvalid, u.Timezone)
	}
	return a.store.UpdateUserProfile(u)
}

// UpdatePrefs saves presentation preferences.
func (a *Auth) UpdatePrefs(ctx context.Context, u *domain.User, p domain.Prefs) error {
	return a.store.UpdateUserPrefs(u.ID, p)
}

// RecordLogin stores call statistics at disconnect.
func (a *Auth) RecordLogin(ctx context.Context, u *domain.User, online time.Duration) error {
	return a.store.RecordLogin(u.ID, a.now(), online)
}

// Promote activates a probationary account and audits it.
func (a *Auth) Promote(ctx context.Context, actor *domain.User, userID string) error {
	if actor != nil && !actor.Role.AtLeast(domain.RoleModerator) {
		return domain.ErrPermission
	}
	if err := a.store.Promote(userID, a.now()); err != nil {
		return err
	}
	entry := domain.AuditEntry{Action: "user.promote", TargetKind: "user", TargetID: userID}
	if actor != nil {
		entry.ActorID, entry.Actor = actor.ID, actor.Handle
	}
	a.auditEvent(entry)
	return nil
}

// MaybePromote applies the D9 rule: probation users become active once both
// probation.days and probation.posts are satisfied.
func (a *Auth) MaybePromote(ctx context.Context, u *domain.User, postCount int) (bool, error) {
	if !u.IsProbation() {
		return false, nil
	}
	if a.cfg.Probation.Days <= 0 && a.cfg.Probation.Posts <= 0 {
		return false, nil
	}
	age := a.now().Sub(u.CreatedAt)
	if age < time.Duration(a.cfg.Probation.Days)*24*time.Hour && a.cfg.Probation.Days > 0 {
		return false, nil
	}
	if postCount < a.cfg.Probation.Posts {
		return false, nil
	}
	if err := a.store.Promote(u.ID, a.now()); err != nil {
		return false, err
	}
	u.Status = domain.StatusActive
	a.auditEvent(domain.AuditEntry{
		Actor: "system", Action: "user.auto_promote", TargetKind: "user", TargetID: u.ID,
	})
	return true, nil
}

// PostCount is the number of non-deleted posts by a user.
func (a *Auth) PostCount(ctx context.Context, userID string) (int, error) {
	return a.store.CountPostsByUser(userID)
}

func trimSignature(sig string, maxLines int) string {
	sig = strings.TrimSpace(sig)
	if sig == "" {
		return ""
	}
	lines := strings.Split(sig, "\n")
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	return strings.Join(lines, "\n")
}

// throttleCheck rejects attempts after repeated failures for this handle/IP.
func (a *Auth) throttleCheck(handle, ipHash string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for _, key := range []string{"h:" + strings.ToLower(handle), "i:" + ipHash} {
		if ipHash == "" && strings.HasPrefix(key, "i:") {
			continue
		}
		if f, ok := a.fails[key]; ok && now.Before(f.until) && f.count >= a.cfg.Limits.LoginAttempts {
			return fmt.Errorf("%w: too many attempts, try again later", domain.ErrRateLimited)
		}
	}
	return nil
}

func (a *Auth) recordFailure(handle, ipHash string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	keys := []string{"h:" + strings.ToLower(handle)}
	if ipHash != "" {
		keys = append(keys, "i:"+ipHash)
	}
	for _, key := range keys {
		f := a.fails[key]
		if f == nil {
			f = &failWindow{}
			a.fails[key] = f
		}
		if now.After(f.until) {
			f.count = 0
		}
		if ok {
			delete(a.fails, key)
			continue
		}
		f.count++
		f.until = now.Add(a.cfg.Limits.LoginWindow)
	}
	_ = a.store.RecordLoginAttempt(ipHash, handle, ok)
}

// checkBans rejects banned handles and IP hashes with a generic message that
// does not reveal which scope matched.
func (a *Auth) checkBans(ctx context.Context, handle, ipHash string) error {
	if a.bans == nil {
		return nil
	}
	banned, reason, err := a.bans(ctx, handle, ipHash)
	if err != nil || !banned {
		return nil
	}
	a.auditEvent(domain.AuditEntry{
		Actor: handle, Action: "auth.banned", TargetKind: "handle", TargetID: handle,
		IPHash: ipHash, Detail: fmt.Sprintf(`{"reason":%q}`, reason),
	})
	return fmt.Errorf("%w: this connection is not welcome here", domain.ErrPermission)
}

func (a *Auth) auditEvent(e domain.AuditEntry) {
	if a.audit != nil {
		a.audit(e)
	}
}

// EncodeParams renders cost parameters for storage in users.pass_params.
func EncodeParams(p PasswordParams) string {
	return "m=" + strconv.FormatUint(uint64(p.Memory), 10) +
		",t=" + strconv.FormatUint(uint64(p.Time), 10) +
		",p=" + strconv.FormatUint(uint64(p.Threads), 10)
}

// ParseParams is the inverse of EncodeParams (used by the admin CLI).
func ParseParams(s string) (PasswordParams, error) {
	var m, t uint64
	var p uint64
	for _, part := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return PasswordParams{}, fmt.Errorf("password params: malformed %q", s)
		}
		v, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return PasswordParams{}, err
		}
		switch kv[0] {
		case "m":
			m = v
		case "t":
			t = v
		case "p":
			p = v
		}
	}
	if m == 0 || t == 0 || p == 0 {
		return PasswordParams{}, errors.New("password params: incomplete")
	}
	return PasswordParams{Memory: uint32(m), Time: uint32(t), Threads: uint8(p), KeyLen: 32}, nil
}
