package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/service"
	"github.com/hacktobeer/hexline/internal/store"
)

type testBoard struct {
	cfg   *config.Config
	addr  string
	srv   *Server
	store *store.Store
}

// syncBuffer is a goroutine-safe bytes.Buffer for reading session output
// while the SSH client's copy goroutine is still writing.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

func startBoard(t *testing.T) *testBoard {
	t.Helper()
	return startBoardOpts(t, nil)
}

func startBoardOpts(t *testing.T, mutate func(*config.Config)) *testBoard {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.DataDir = dir
	cfg.Database.Path = "test.db"
	cfg.Storage.FilesDir = "files"
	cfg.Transport.SSH.Address = "127.0.0.1:" + freePort(t)
	cfg.Transport.SSH.HostKeyPath = "host_ed25519"
	cfg.Transport.SSH.MaxSessions = 20
	cfg.Transport.SSH.MaxPerIP = 20
	cfg.Transport.SSH.IdleTimeout = 2 * time.Minute
	if mutate != nil {
		mutate(cfg)
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := st.Seed(); err != nil {
		t.Fatal(err)
	}
	auth := service.NewAuth(st, cfg, func(e domain.AuditEntry) { _ = st.RecordAudit(e) })
	u := &domain.User{Handle: "tester", Status: domain.StatusActive, Role: domain.RoleUser,
		PassHash: mustHash(t, auth, "test-password-1"), PassParams: service.EncodeParams(auth.Hasher().Params()),
		Prefs: domain.DefaultPrefs()}
	if err := st.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	broker := hub.NewBroker(16)
	admin := service.NewAdmin(st, cfg, broker)
	auth.SetBanChecker(admin.IsBanned)
	srv, err := New(Deps{
		Cfg: cfg, Store: st, Auth: auth,
		Boards: service.NewBoards(st, cfg), Mail: service.NewMail(st, cfg),
		Files: service.NewFiles(st, cfg), Community: service.NewCommunity(st, cfg, broker),
		Admin: admin, Broker: broker, Presence: hub.NewPresence(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx)
	waitForPort(t, cfg.Transport.SSH.Address)
	return &testBoard{cfg: cfg, addr: cfg.Transport.SSH.Address, srv: srv, store: st}
}

func mustHash(t *testing.T, a *service.Auth, pw string) string {
	t.Helper()
	h, err := a.Hasher().Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func waitForPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server never listened on %s", addr)
}

func dial(t *testing.T, addr, user, password string) *gossh.Client {
	t.Helper()
	client, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{gossh.Password(password)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestExecWhoami(t *testing.T) {
	b := startBoard(t)
	client := dial(t, b.addr, "tester", "test-password-1")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, err := sess.Output("whoami")
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if strings.TrimSpace(string(out)) != "tester" {
		t.Fatalf("whoami = %q", out)
	}
}

func TestBadPasswordRejected(t *testing.T) {
	b := startBoard(t)
	_, err := gossh.Dial("tcp", b.addr, &gossh.ClientConfig{
		User: "tester", Auth: []gossh.AuthMethod{gossh.Password("wrong-password")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("bad password was accepted")
	}
}

func TestUnknownHandleGetsRegistrationSession(t *testing.T) {
	b := startBoard(t)
	client := dial(t, b.addr, "newcaller", "brand-new-password")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	modes := gossh.TerminalModes{gossh.ECHO: 1}
	if err := sess.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		t.Fatal(err)
	}
	var buf syncBuffer
	sess.Stdout = &buf
	sess.Stdin = strings.NewReader("")
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	deadline := time.After(3 * time.Second)
	for {
		if strings.Contains(buf.String(), "New caller") {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("registration screen never rendered; got %q", buf.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestTUIConnectsAndQuits(t *testing.T) {
	b := startBoard(t)
	client := dial(t, b.addr, "tester", "test-password-1")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	modes := gossh.TerminalModes{gossh.ECHO: 1}
	if err := sess.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	go io.Copy(&out, stdout)
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), "Boards") {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "Boards") {
		t.Fatalf("main menu not rendered: %q", out.String())
	}
	if _, err := fmt.Fprint(stdin, "q"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("session did not close after q")
	}
	if b.srv.ActiveSessions() != 0 {
		t.Fatalf("active sessions = %d after quit", b.srv.ActiveSessions())
	}
}

func TestUploadDownloadRoundTrip(t *testing.T) {
	b := startBoard(t)
	client := dial(t, b.addr, "tester", "test-password-1")

	payload := []byte("hello from the pipe\x00\x01binary-safe\n")
	up, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	up.Stdin = bytes.NewReader(payload)
	out, err := up.Output("put UPLOADS/roundtrip.bin")
	if err != nil {
		t.Fatalf("put: %v (%s)", err, out)
	}
	if !strings.Contains(string(out), "stored") {
		t.Fatalf("put output = %q", out)
	}

	down, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	got, err := down.Output("get UPLOADS/roundtrip.bin")
	if err != nil {
		t.Fatalf("get: %v (%s)", err, got)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestDownloadRejectsTraversal(t *testing.T) {
	b := startBoard(t)
	client := dial(t, b.addr, "tester", "test-password-1")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("get UPLOADS/../../etc/passwd")
	if err == nil {
		t.Fatalf("traversal was accepted: %q", out)
	}
	if strings.Contains(string(out), "root:") {
		t.Fatal("leaked /etc/passwd")
	}
}

func TestBannedHandleRejectedOverSSH(t *testing.T) {
	b := startBoard(t)
	// The board's store is private to startBoard; create the ban through the
	// same database file via the admin CLI-equivalent path.
	ban := &domain.Ban{Scope: "handle", Value: "tester", Reason: "spam"}
	if err := b.store.CreateBan(ban); err != nil {
		t.Fatal(err)
	}
	_, err := gossh.Dial("tcp", b.addr, &gossh.ClientConfig{
		User: "tester", Auth: []gossh.AuthMethod{gossh.Password("test-password-1")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("banned handle was allowed to authenticate")
	}
}

func TestRapidKeysAreReplayedIndividually(t *testing.T) {
	b := startBoard(t)
	client := dial(t, b.addr, "tester", "test-password-1")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm-256color", 24, 80, gossh.TerminalModes{gossh.ECHO: 1}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	sess.Stdout = &out
	sess.Stderr = &out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	// Wait for the first paint, then send two keys in one write: the app must
	// replay them separately or the quit key is swallowed by "jq".
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), "Boards") {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "Boards") {
		t.Fatalf("menu did not render: %q", out.String())
	}
	if _, err := io.WriteString(stdin, "jq"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("session did not close after batched jq")
	}
}

func (b *testBoard) user(t *testing.T, handle string) *domain.User {
	t.Helper()
	u, err := b.store.UserByHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (b *testBoard) enrollKey(t *testing.T, u *domain.User) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	if err := b.store.AddSSHKey(u.ID, Fingerprint(pub), string(gossh.MarshalAuthorizedKey(pub))); err != nil {
		t.Fatal(err)
	}
	return signer
}

func dialKey(t *testing.T, addr string, user string, signer gossh.Signer) (*gossh.Client, error) {
	t.Helper()
	return gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User: user, Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
}

func TestPublicKeyLoginWorksAndHonoursBans(t *testing.T) {
	b := startBoard(t)
	signer := b.enrollKey(t, b.user(t, "tester"))

	client, err := dialKey(t, b.addr, "tester", signer)
	if err != nil {
		t.Fatalf("key login: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("whoami")
	if err != nil || strings.TrimSpace(string(out)) != "tester" {
		t.Fatalf("whoami over key auth = %q, %v", out, err)
	}
	client.Close()

	if err := b.store.CreateBan(&domain.Ban{Scope: "handle", Value: "tester", Reason: "spam"}); err != nil {
		t.Fatal(err)
	}
	if _, err := dialKey(t, b.addr, "tester", signer); err == nil {
		t.Fatal("banned handle still logged in with a key")
	}
}

func TestPublicKeyAuthCanBeDisabled(t *testing.T) {
	b := startBoardOpts(t, func(cfg *config.Config) {
		cfg.Transport.SSH.AllowPubkey = false
	})
	signer := b.enrollKey(t, b.user(t, "tester"))
	if _, err := dialKey(t, b.addr, "tester", signer); err == nil {
		t.Fatal("key auth accepted while allow_pubkey = false")
	}
}

func TestGuestIsBlockedByIPBan(t *testing.T) {
	b := startBoard(t)
	ipHash := b.srv.HashIP("127.0.0.1:12345")
	if err := b.store.CreateBan(&domain.Ban{Scope: "ip", Value: ipHash, Reason: "abuse"}); err != nil {
		t.Fatal(err)
	}
	_, err := gossh.Dial("tcp", b.addr, &gossh.ClientConfig{
		User: "guest", Auth: []gossh.AuthMethod{gossh.Password("anything")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("banned IP connected as guest")
	}
}

func TestUploadOverCapIsRejected(t *testing.T) {
	b := startBoardOpts(t, func(cfg *config.Config) {
		cfg.Storage.MaxUploadBytes = 16
	})
	client := dial(t, b.addr, "tester", "test-password-1")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	sess.Stdin = bytes.NewReader(make([]byte, 100))
	out, err := sess.Output("put UPLOADS/big.bin")
	if err == nil {
		t.Fatalf("oversized upload accepted: %q", out)
	}
	if !strings.Contains(string(out), "limit") {
		t.Fatalf("unhelpful error: %q", out)
	}
}

func TestTUIDoesNotLeaveStaleTextOnNavigation(t *testing.T) {
	b := startBoard(t)
	client := dial(t, b.addr, "tester", "test-password-1")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm-256color", 24, 80, gossh.TerminalModes{gossh.ECHO: 1}); err != nil {
		t.Fatal(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	sess.Stdout = &out
	sess.Stderr = &out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), "Boards") {
		time.Sleep(10 * time.Millisecond)
	}
	// Help is shorter than the menu; rendering it must erase the leftover
	// cells, which Bubble Tea only does when it knows the terminal width.
	if _, err := io.WriteString(stdin, "?"); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "\x1b[K") || strings.Contains(out.String(), "\x1b[J") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no line-erase sequence after navigation: the renderer has no terminal size")
}

func TestCommandSessionsRespectConnectionLimits(t *testing.T) {
	b := startBoardOpts(t, func(cfg *config.Config) {
		cfg.Transport.SSH.MaxPerIP = 1
		cfg.Transport.SSH.MaxSessions = 4
	})

	// Hold the single per-IP slot with an interactive session.
	client := dial(t, b.addr, "tester", "test-password-1")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm-256color", 24, 80, gossh.TerminalModes{gossh.ECHO: 1}); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	sess.Stdout = &out
	sess.Stderr = &out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), "Boards") {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "Boards") {
		t.Fatalf("menu did not render: %q", out.String())
	}

	// A one-shot command from the same host must now be refused: before the
	// fix, `ssh bbs whoami` bypassed max_per_ip entirely.
	client2, err := gossh.Dial("tcp", b.addr, &gossh.ClientConfig{
		User: "tester", Auth: []gossh.AuthMethod{gossh.Password("test-password-1")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	sess2, err := client2.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess2.Close()
	out2, err := sess2.Output("whoami")
	if err == nil {
		t.Fatalf("command session bypassed the per-IP limit: %q", out2)
	}
	if !strings.Contains(string(out2), "busy") {
		t.Fatalf("expected a busy message, got %q", out2)
	}
}

func TestGuestCanBeDisabled(t *testing.T) {
	b := startBoardOpts(t, func(cfg *config.Config) {
		cfg.Guest.Enabled = false
	})
	_, err := gossh.Dial("tcp", b.addr, &gossh.ClientConfig{
		User: "guest", Auth: []gossh.AuthMethod{gossh.Password("anything")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("guest logged in while guest.enabled = false")
	}
}
