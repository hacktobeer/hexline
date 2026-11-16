// Package ssh binds hexline to a single SSH listener. It is the only
// transport (decision D1).
package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	gossh "golang.org/x/crypto/ssh"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/service"
	"github.com/hacktobeer/hexline/internal/store"
	"github.com/hacktobeer/hexline/internal/tui"
)

// Deps are the collaborators a server needs.
type Deps struct {
	Cfg       *config.Config
	Store     *store.Store
	Auth      *service.Auth
	Boards    *service.Boards
	Mail      *service.Mail
	Files     *service.Files
	Community *service.Community
	Admin     *service.Admin
	Broker    *hub.Broker
	Presence  *hub.Presence
	Log       *slog.Logger
}

// Server serves the BBS over SSH.
type Server struct {
	deps Deps
	log  *slog.Logger

	active   atomic.Int64
	total    atomic.Uint64
	lastFree atomic.Int64
	mu       sync.Mutex
	perIP    map[string]int
	ipSecret []byte
	srv      *ssh.Server
}

type ctxKey string

const (
	ctxUserID   ctxKey = "hexline.user_id"
	ctxHandle   ctxKey = "hexline.handle"
	ctxRegister ctxKey = "hexline.register_password"
	ctxGuest    ctxKey = "hexline.guest"
)

// New builds a server, creating the host key on first run.
func New(d Deps) (*Server, error) {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	keyPath := d.Cfg.HostKeyPath()
	if err := ensureHostKey(keyPath); err != nil {
		return nil, err
	}
	secret, err := secretFromFile(keyPath)
	if err != nil {
		return nil, err
	}
	s := &Server{deps: d, log: d.Log, perIP: map[string]int{}, ipSecret: secret}

	opts := []ssh.Option{
		wish.WithAddress(d.Cfg.Transport.SSH.Address),
		wish.WithHostKeyPath(keyPath),
		wish.WithIdleTimeout(d.Cfg.Transport.SSH.IdleTimeout),
		wish.WithVersion("hexline"),
		wish.WithBanner(d.Cfg.Transport.SSH.BannerText + "\r\n"),
		wish.WithPasswordAuth(s.passwordAuth),
		wish.WithMiddleware(func(next ssh.Handler) ssh.Handler {
			return s.dispatch
		}),
	}
	if d.Cfg.Transport.SSH.AllowPubkey {
		opts = append(opts, wish.WithPublicKeyAuth(s.publicKeyAuth))
	}
	srv, err := wish.NewServer(opts...)
	if err != nil {
		return nil, fmt.Errorf("ssh: server: %w", err)
	}
	s.srv = srv
	return s, nil
}

// Addr reports the listener address (useful when tests bind :0).
func (s *Server) Addr() string {
	if s.srv == nil {
		return ""
	}
	return s.srv.Addr
}

// Serve runs until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if errors.Is(err, ssh.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
		return nil
	}
}

// ActiveSessions reports live sessions.
func (s *Server) ActiveSessions() int64 { return s.active.Load() }

// TotalSessions reports sessions since start.
func (s *Server) TotalSessions() uint64 { return s.total.Load() }

// HashIP returns the stable HMAC used for abuse correlation and audit.
func (s *Server) HashIP(addr string) string {
	host := addr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		host = addr[:i]
	}
	mac := hmac.New(sha256.New, s.ipSecret)
	mac.Write([]byte(host))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:22]
}

func (s *Server) passwordAuth(ctx ssh.Context, password string) bool {
	handle := strings.TrimSpace(ctx.User())
	ipHash := s.HashIP(ctx.RemoteAddr().String())

	if strings.EqualFold(handle, "guest") {
		if !s.deps.Cfg.Guest.Enabled {
			return false
		}
		if banned, _, err := s.deps.Admin.IsBanned(ctx, "", ipHash); err == nil && banned {
			return false
		}
		ctx.SetValue(ctxGuest, true)
		return true
	}
	if handle == "" {
		return false
	}
	u, err := s.deps.Auth.Authenticate(ctx, handle, password, ipHash)
	switch {
	case err == nil:
		ctx.SetValue(ctxUserID, u.ID)
		ctx.SetValue(ctxHandle, u.Handle)
		return true
	case errors.Is(err, domain.ErrNotFound):
		// Unknown handle: allow connection only so the caller can register.
		if !s.deps.Cfg.Registration.Open {
			return false
		}
		ctx.SetValue(ctxRegister, password)
		ctx.SetValue(ctxHandle, handle)
		return true
	default:
		s.log.Info("ssh auth rejected", "handle", handle, "ip_hash", ipHash, "err", err)
		return false
	}
}

func (s *Server) publicKeyAuth(ctx ssh.Context, key ssh.PublicKey) bool {
	fp := Fingerprint(key)
	userID, err := s.deps.Store.UserIDBySSHKey(fp)
	if err != nil {
		return false
	}
	u, err := s.deps.Store.UserByID(userID)
	if err != nil || !u.CanLogin() {
		return false
	}
	// Key auth must honour bans exactly like password auth, otherwise a banned
	// caller only has to enroll a key to return.
	if banned, _, err := s.deps.Admin.IsBanned(ctx, u.Handle, s.HashIP(ctx.RemoteAddr().String())); err == nil && banned {
		return false
	}
	ctx.SetValue(ctxUserID, u.ID)
	ctx.SetValue(ctxHandle, u.Handle)
	return true
}

// Fingerprint renders the stable key identifier stored in ssh_keys:
// base64url(SHA-256(key blob)), without the SHA256: prefix.
func Fingerprint(key ssh.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(sha256Sum(key.Marshal()))
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// dispatch separates interactive sessions from one-shot commands. Both go
// through the same connection caps: `ssh bbs get` must not dodge the per-IP
// or total session limits that interactive callers obey.
func (s *Server) dispatch(sess ssh.Session) {
	if len(sess.Command()) > 0 {
		_, release, ok := s.acquireNode(sess)
		if !ok {
			return
		}
		defer release()
		s.runCommand(sess)
		return
	}
	s.runSession(sess)
}

// acquireNode enforces the per-IP and total session caps and returns the
// client IP plus a release function. It is shared by interactive and
// one-shot sessions so neither can bypass the limits.
func (s *Server) acquireNode(sess ssh.Session) (string, func(), bool) {
	ip := sess.RemoteAddr().String()
	if !s.acquireIP(ip) {
		fmt.Fprint(sess, "All nodes for your address are busy. Try again later.\r\n")
		_ = sess.Exit(1)
		return ip, nil, false
	}
	if max := s.deps.Cfg.Transport.SSH.MaxSessions; s.active.Load() >= int64(max) {
		s.releaseIP(ip)
		fmt.Fprint(sess, "The board is full. Try again later.\r\n")
		_ = sess.Exit(1)
		return ip, nil, false
	}
	s.active.Add(1)
	s.total.Add(1)
	return ip, func() {
		s.active.Add(-1)
		s.releaseIP(ip)
		s.releaseMemoryWhenIdle()
	}, true
}

func (s *Server) runSession(sess ssh.Session) {
	ip, release, ok := s.acquireNode(sess)
	if !ok {
		return
	}
	defer release()

	ctx := sess.Context()
	user, err := s.sessionUser(ctx)
	if err != nil {
		fmt.Fprintf(sess, "Login failed: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}
	ipHash := s.HashIP(ip)
	nodeID := newSessionID()
	node := s.deps.Presence.Join(nodeID, user.ID, user.Handle, ipHash)
	defer s.deps.Presence.Leave(nodeID)

	started := time.Now()
	sessionRow := nodeID
	if err := s.deps.Store.StartSession(sessionRow, user.ID, node.Node, ipHash, sess.Context().ClientVersion()); err != nil {
		s.log.Warn("session row", "err", err)
	}
	defer func() {
		if err := s.deps.Auth.RecordLogin(context.Background(), user, time.Since(started)); err != nil {
			s.log.Warn("record login", "err", err)
		}
		if err := s.deps.Store.EndSession(sessionRow); err != nil {
			s.log.Warn("end session", "err", err)
		}
		s.deps.Broker.Publish(hub.Event{
			Kind: hub.KindPresence, Scope: "*", FromID: user.ID, From: user.Handle,
			Text: user.Handle + " hung up",
		})
	}()

	s.deps.Broker.Publish(hub.Event{
		Kind: hub.KindPresence, Scope: "*", FromID: user.ID, From: user.Handle,
		Text: user.Handle + " called in",
	})

	sess2 := &tui.Session{
		User: user, Node: node.Node, IPHash: ipHash, Started: started,
		ReadOnly: user.IsGuest || user.Status == domain.StatusSuspended,
	}
	if pw, ok := ctx.Value(ctxRegister).(string); ok && pw != "" {
		sess2.PendingHandle = user.Handle
		sess2.PendingPassword = pw
		sess2.User = nil
		sess2.ReadOnly = false
	}
	app := tui.New(s.deps.Cfg, s.deps.Store, s.deps.Auth, s.deps.Boards, s.deps.Mail,
		s.deps.Files, s.deps.Community, s.deps.Admin, s.deps.Broker, sess2)
	app.Presence = s.deps.Presence
	app.SessionID = nodeID
	app.Touch = func(activity string) { s.deps.Presence.Touch(nodeID, activity) }

	program := tea.NewProgram(app,
		tea.WithInput(sess),
		tea.WithOutput(sess),
		tea.WithAltScreen(),
	)
	// A TUI session ends in one of two ways: the program exits (quit key) or
	// the client goes away. Without watching the SSH context, a dead client
	// leaves the program writing into a closed channel and the node occupied
	// forever.
	done := make(chan error, 1)
	go func() {
		_, err := program.Run()
		done <- err
	}()
	// Bubble Tea only erases stale cells when it knows the terminal size. We
	// are not using wish's bubbletea middleware, so forward the PTY size and
	// every resize ourselves; without this, navigating from a long screen to a
	// short one leaves the old text on screen.
	go func() {
		pty, windows, ok := sess.Pty()
		if !ok {
			return
		}
		program.Send(tea.WindowSizeMsg{Width: pty.Window.Width, Height: pty.Window.Height})
		for w := range windows {
			program.Send(tea.WindowSizeMsg{Width: w.Width, Height: w.Height})
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			s.log.Warn("session ended with error", "handle", user.Handle, "err", err)
		}
	case <-sess.Context().Done():
		program.Kill()
		<-done
		s.log.Debug("session closed by client", "handle", user.Handle)
	}
}

func (s *Server) sessionUser(ctx ssh.Context) (*domain.User, error) {
	if guest, _ := ctx.Value(ctxGuest).(bool); guest {
		return &domain.User{Handle: "guest", IsGuest: true, Status: domain.StatusActive,
			Role: domain.RoleUser, Prefs: domain.DefaultPrefs()}, nil
	}
	id, _ := ctx.Value(ctxUserID).(string)
	if id == "" {
		// Registration pending: build the not-yet-created user shell.
		handle, _ := ctx.Value(ctxHandle).(string)
		if handle == "" {
			return nil, errors.New("no handle supplied")
		}
		return &domain.User{Handle: handle, Status: domain.StatusProbation,
			Role: domain.RoleUser, Prefs: domain.DefaultPrefs()}, nil
	}
	return s.deps.Store.UserByID(id)
}

// runCommand serves non-interactive commands such as `ssh bbs get AREA/FILE`.
func (s *Server) runCommand(sess ssh.Session) {
	user, err := s.sessionUser(sess.Context())
	if err != nil {
		fmt.Fprintf(sess, "error: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}
	// A caller who connected with an unknown handle has not registered yet;
	// they may finish registration but must not run commands (get/whoami/put)
	// under a probation shell. Guest is the deliberate anonymous reader.
	if user.ID == "" && !user.IsGuest {
		fmt.Fprint(sess, "error: complete registration first\r\n")
		_ = sess.Exit(1)
		return
	}
	args := sess.Command()
	switch args[0] {
	case "get":
		if len(args) != 2 {
			fmt.Fprint(sess, "usage: ssh <board> get AREA/FILE > out\r\n")
			_ = sess.Exit(2)
			return
		}
		area, filename, ok := splitSpec(args[1])
		if !ok {
			fmt.Fprint(sess, "usage: ssh <board> get AREA/FILE > out\r\n")
			_ = sess.Exit(2)
			return
		}
		rc, file, err := s.deps.Files.OpenDownload(context.Background(), user, area, filename)
		if err != nil {
			s.commandError(sess, "get", user.Handle, err)
			_ = sess.Exit(1)
			return
		}
		defer rc.Close()
		n, err := io.Copy(sess, rc)
		if err != nil {
			s.log.Warn("download interrupted", "file", file.Filename, "err", err)
			_ = sess.Exit(1)
			return
		}
		s.log.Info("download", "handle", user.Handle, "file", file.Filename, "bytes", n)
		_ = sess.Exit(0)
	case "put":
		if len(args) != 2 {
			fmt.Fprint(sess, "usage: ssh <board> put AREA/FILE < local-file\r\n")
			_ = sess.Exit(2)
			return
		}
		area, filename, ok := splitSpec(args[1])
		if !ok {
			fmt.Fprint(sess, "usage: ssh <board> put AREA/FILE < local-file\r\n")
			_ = sess.Exit(2)
			return
		}
		file, err := s.deps.Files.UploadStream(context.Background(), user, area, filename, "",
			sess, s.deps.Cfg.Storage.MaxUploadBytes)
		if err != nil {
			s.commandError(sess, "put", user.Handle, err)
			_ = sess.Exit(1)
			return
		}
		s.log.Info("upload", "handle", user.Handle, "file", file.Filename, "bytes", file.SizeBytes)
		fmt.Fprintf(sess, "stored %s/%s (%d bytes, sha256 %s)\r\n", area, file.Filename, file.SizeBytes, file.SHA256)
		_ = sess.Exit(0)
	case "whoami":
		fmt.Fprintf(sess, "%s\r\n", user.Handle)
		_ = sess.Exit(0)
	case "help", "-h", "--help":
		fmt.Fprint(sess, "hexline commands:\r\n  get AREA/FILE   stream a file from a file area\r\n  put AREA/FILE   upload stdin into a file area\r\n  whoami\r\n")
		_ = sess.Exit(0)
	default:
		fmt.Fprintf(sess, "unknown command %q\r\n", args[0])
		_ = sess.Exit(2)
	}
}

func splitSpec(spec string) (area, name string, ok bool) {
	i := strings.Index(spec, "/")
	if i <= 0 || i == len(spec)-1 {
		return "", "", false
	}
	return spec[:i], spec[i+1:], true
}

// userFacing reports whether err is safe to show a caller. Domain errors
// carry no server internals; filesystem errors embed absolute paths and must
// be kept server-side.
func userFacing(err error) bool {
	for e := err; e != nil; {
		switch e {
		case domain.ErrNotFound, domain.ErrPermission, domain.ErrInvalid,
			domain.ErrQuota, domain.ErrProbation, domain.ErrConflict,
			domain.ErrRateLimited, domain.ErrUnavailable, domain.ErrClosed,
			domain.ErrSuspended:
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// commandError prints an error for a one-shot command: user-facing errors are
// shown as-is, internal errors are logged and replaced with a generic message
// so filesystem paths never reach the client.
func (s *Server) commandError(sess ssh.Session, command, handle string, err error) {
	if userFacing(err) {
		fmt.Fprintf(sess, "error: %v\r\n", err)
		return
	}
	s.log.Warn("command failed", "command", command, "handle", handle, "err", err)
	fmt.Fprint(sess, "error: an internal error occurred; please try again later\r\n")
}

func (s *Server) acquireIP(ip string) bool {
	host := ip
	if i := strings.LastIndex(ip, ":"); i > 0 {
		host = ip[:i]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perIP[host] >= s.deps.Cfg.Transport.SSH.MaxPerIP {
		return false
	}
	s.perIP[host]++
	return true
}

func (s *Server) releaseIP(ip string) {
	host := ip
	if i := strings.LastIndex(ip, ":"); i > 0 {
		host = ip[:i]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perIP[host] <= 1 {
		delete(s.perIP, host)
		return
	}
	s.perIP[host]--
}

// releaseMemoryWhenIdle returns freed heap to the OS once the board is empty.
// Argon2 and per-session render buffers can leave a large footprint behind;
// Go does not hand memory back promptly on its own. Rate-limited so churn
// cannot trigger repeated collections.
func (s *Server) releaseMemoryWhenIdle() {
	if s.active.Load() != 0 {
		return
	}
	now := time.Now().Unix()
	last := s.lastFree.Load()
	if now-last < 30 {
		return
	}
	if s.lastFree.CompareAndSwap(last, now) {
		debug.FreeOSMemory()
		s.log.Debug("released idle heap")
	}
}

func newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("node-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func ensureHostKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := gossh.MarshalPrivateKey(priv, "hexline host key")
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return fmt.Errorf("ssh: write host key: %w", err)
	}
	return nil
}

func secretFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ssh: read host key: %w", err)
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}
