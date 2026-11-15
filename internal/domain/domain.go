// Package domain holds the shared entities, errors and rules of hexline.
// It has no dependencies outside the standard library.
package domain

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Role is a user's privilege level. Roles are ordered.
type Role string

// Roles, lowest to highest privilege.
const (
	RoleUser      Role = "user"
	RoleModerator Role = "moderator"
	RoleSysop     Role = "sysop"
)

// Rank returns an ordering for role comparisons (-1 for unknown roles).
func (r Role) Rank() int {
	switch r {
	case RoleUser:
		return 0
	case RoleModerator:
		return 1
	case RoleSysop:
		return 2
	}
	return -1
}

// AtLeast reports whether r is at least as privileged as min.
func (r Role) AtLeast(min Role) bool { return r.Rank() >= min.Rank() }

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r.Rank() >= 0 }

// Status is an account lifecycle state.
type Status string

// Account states.
const (
	StatusActive    Status = "active"
	StatusProbation Status = "probation"
	StatusSuspended Status = "suspended"
	StatusDeleted   Status = "deleted"
)

// Prefs are per-user presentation settings. ANSI is the only one that changes
// rendering; terminal width always comes from the real terminal.
type Prefs struct {
	ANSI bool `json:"ansi"`
}

// DefaultPrefs returns colour output on.
func DefaultPrefs() Prefs { return Prefs{ANSI: true} }

// User is an account.
type User struct {
	ID         string
	Handle     string
	Email      string
	RealName   string
	Location   string
	Signature  string
	Timezone   string
	Role       Role
	Status     Status
	CreatedAt  time.Time
	LastCallAt time.Time
	Calls      int
	TimeOnline time.Duration
	PassHash   string
	PassParams string
	Prefs      Prefs
	SSHKeys    []string
	PromotedAt time.Time
	IsGuest    bool
}

// CanWrite reports whether the account may create content. Guests and
// suspended/deleted accounts cannot.
func (u *User) CanWrite() bool {
	return !u.IsGuest && (u.Status == StatusActive || u.Status == StatusProbation)
}

// IsProbation reports whether the account is still on probation (D3).
func (u *User) IsProbation() bool { return u.Status == StatusProbation }

// CanLogin reports whether the account may open a session.
func (u *User) CanLogin() bool {
	return u.Status == StatusActive || u.Status == StatusProbation
}

// ACL lists the minimum roles allowed to perform an action.
type ACL struct {
	Read     []Role
	Post     []Role
	Moderate []Role
}

// DefaultACL allows all users to read and post; only moderators may moderate.
func DefaultACL() ACL {
	return ACL{
		Read:     []Role{RoleUser},
		Post:     []Role{RoleUser},
		Moderate: []Role{RoleModerator},
	}
}

// ParseACL parses a comma-separated role list such as "moderator,sysop".
// An empty string means "user and above".
func ParseACL(s string) ([]Role, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return []Role{RoleUser}, nil
	}
	var out []Role
	for _, part := range strings.Split(s, ",") {
		r := Role(strings.TrimSpace(strings.ToLower(part)))
		if !r.Valid() {
			return nil, fmt.Errorf("%w: unknown role %q", ErrInvalid, part)
		}
		out = append(out, r)
	}
	return out, nil
}

// FormatACL renders a role list back to storage form.
func FormatACL(roles []Role) string {
	parts := make([]string, len(roles))
	for i, r := range roles {
		parts[i] = string(r)
	}
	return strings.Join(parts, ",")
}

func allowed(roles []Role, r Role) bool {
	if len(roles) == 0 {
		return r.AtLeast(RoleUser)
	}
	for _, x := range roles {
		if r.AtLeast(x) {
			return true
		}
	}
	return false
}

// CanRead reports whether role may read the area.
func (a ACL) CanRead(r Role) bool { return allowed(a.Read, r) }

// CanPost reports whether role may post in the area.
func (a ACL) CanPost(r Role) bool { return allowed(a.Post, r) }

// CanModerate reports whether role may moderate the area.
func (a ACL) CanModerate(r Role) bool { return allowed(a.Moderate, r) }

// Area is a message conference.
type Area struct {
	ID               string
	Tag              string
	Name             string
	Description      string
	SortOrder        int
	ACL              ACL
	RetentionDays    int
	RateLimitPerHour int
	IsPublic         bool
	CreatedAt        time.Time
}

// Thread is a conversation within an area.
type Thread struct {
	ID         string
	AreaID     string
	AreaTag    string
	Subject    string
	AuthorID   string
	Author     string
	CreatedAt  time.Time
	LastPostAt time.Time
	PostCount  int
	Sticky     bool
	Locked     bool
	Deleted    bool
	Unread     int
}

// Post is a single message.
type Post struct {
	ID        int64
	ThreadID  string
	AuthorID  string
	Author    string
	Body      string
	CreatedAt time.Time
	EditedAt  time.Time
	Deleted   bool
	DeletedBy string
	DeleteWhy string
}

// Mail is a private message.
type Mail struct {
	ID        string
	FromID    string
	From      string
	ToID      string
	To        string
	Subject   string
	Body      string
	CreatedAt time.Time
	ReadAt    time.Time
	ThreadKey string
}

// FileArea is a download area.
type FileArea struct {
	ID          string
	Tag         string
	Name        string
	Description string
	SortOrder   int
	ACL         ACL
	QuotaBytes  int64
	CreatedAt   time.Time
}

// File is an uploaded artifact.
type File struct {
	ID            string
	AreaID        string
	AreaTag       string
	Filename      string
	StoredPath    string
	SizeBytes     int64
	SHA256        string
	Description   string
	UploaderID    string
	Uploader      string
	UploadedAt    time.Time
	DownloadCount int
	ScanStatus    string
	Rating        float64
	RatingCount   int
}

// Oneliner is a short public message.
type Oneliner struct {
	ID        int64
	AuthorID  string
	Author    string
	Body      string
	CreatedAt time.Time
	Hidden    bool
}

// Poll is a community vote.
type Poll struct {
	ID         string
	Question   string
	CreatedBy  string
	CreatedAt  time.Time
	ClosesAt   time.Time
	Hidden     bool
	Options    []PollOption
	TotalVotes int
	MyVote     int64
}

// PollOption is one choice in a poll.
type PollOption struct {
	ID     int64
	PollID string
	Label  string
	Sort   int
	Votes  int
}

// Bulletin is a sysop notice.
type Bulletin struct {
	ID        string
	Title     string
	Body      string
	Sort      int
	Active    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Ban blocks a handle or an IP hash.
type Ban struct {
	ID        string
	Scope     string // "handle" or "ip"
	Value     string
	Reason    string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuditEntry is a privileged action record.
type AuditEntry struct {
	ID         int64
	At         time.Time
	ActorID    string
	Actor      string
	Action     string
	TargetKind string
	TargetID   string
	Detail     string
	IPHash     string
}

// SessionInfo describes a live node.
type SessionInfo struct {
	ID        string
	UserID    string
	Handle    string
	Node      int
	StartedAt time.Time
	IdleFor   time.Duration
	Activity  string
	RemoteIP  string
}

// Errors returned by services; screens map them to friendly text.
var (
	ErrNotFound    = errors.New("not found")
	ErrPermission  = errors.New("permission denied")
	ErrConflict    = errors.New("conflict")
	ErrRateLimited = errors.New("rate limited")
	ErrQuota       = errors.New("quota exceeded")
	ErrInvalid     = errors.New("invalid input")
	ErrSuspended   = errors.New("account suspended")
	ErrProbation   = errors.New("not available during probation")
	ErrClosed      = errors.New("thread closed")
	ErrUnavailable = errors.New("temporarily unavailable")
)

// HandleRules describes the accepted handle shape.
var handleRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{1,19}$`)

// reservedHandles are not available for registration.
var reservedHandles = map[string]bool{
	"sysop": true, "admin": true, "root": true, "guest": true, "new": true,
	"system": true, "hexline": true, "moderator": true, "mod": true,
}

// ValidateHandle checks length, charset and reserved names.
func ValidateHandle(h string) error {
	if err := ValidateHandleShape(h); err != nil {
		return err
	}
	if reservedHandles[strings.ToLower(strings.TrimSpace(h))] {
		return fmt.Errorf("%w: handle %q is reserved", ErrInvalid, h)
	}
	return nil
}

// ValidateHandleShape checks length and charset, allowing reserved names.
// Only the sysop CLI may use this.
func ValidateHandleShape(h string) error {
	h = strings.TrimSpace(h)
	if h == "" {
		return fmt.Errorf("%w: handle is required", ErrInvalid)
	}
	if !handleRe.MatchString(h) {
		return fmt.Errorf("%w: handle must be 2-20 chars, start with a letter, and use letters, digits, _ . -", ErrInvalid)
	}
	return nil
}

// ValidatePassword enforces a minimum password length (max 128 for argon2 sanity).
func ValidatePassword(p string) error {
	if len(p) < 8 {
		return fmt.Errorf("%w: password must be at least 8 characters", ErrInvalid)
	}
	if len(p) > 128 {
		return fmt.Errorf("%w: password must be at most 128 characters", ErrInvalid)
	}
	return nil
}

// ValidateSubject checks a thread subject.
func ValidateSubject(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("%w: subject is required", ErrInvalid)
	}
	if len(s) > 120 {
		return fmt.Errorf("%w: subject must be at most 120 characters", ErrInvalid)
	}
	if strings.ContainsAny(s, "\r\n") {
		return fmt.Errorf("%w: subject must be a single line", ErrInvalid)
	}
	return nil
}

// ValidateBody checks a post/body against configured caps.
func ValidateBody(body string, maxBytes, maxLines int) error {
	body = strings.TrimSpace(body)
	if body == "" {
		return fmt.Errorf("%w: message body is empty", ErrInvalid)
	}
	if len(body) > maxBytes {
		return fmt.Errorf("%w: message is %d bytes, limit is %d", ErrInvalid, len(body), maxBytes)
	}
	lines := 1 + strings.Count(body, "\n")
	if maxLines > 0 && lines > maxLines {
		return fmt.Errorf("%w: message has %d lines, limit is %d", ErrInvalid, lines, maxLines)
	}
	return nil
}

// SubjectReply prefixes s with "Re: " unless already present.
func SubjectReply(s string) string {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToLower(t), "re:") {
		return t
	}
	return "Re: " + t
}

// Quote builds a quote header + indented body for replies.
func Quote(author, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s wrote:\n", author)
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		b.WriteString("> ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
