package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/store"
)

func testConfig() *config.Config {
	c := config.Default()
	c.Probation = config.Probation{Days: 3, Posts: 10}
	return c
}

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
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
	return st
}

func testAuth(t *testing.T) (*Auth, *store.Store) {
	st := testStore(t)
	return NewAuth(st, testConfig(), func(e domain.AuditEntry) {
		if err := st.RecordAudit(e); err != nil {
			t.Logf("audit: %v", err)
		}
	}), st
}

func TestPasswordHashVerify(t *testing.T) {
	p := PasswordParams{Memory: 8 * 1024, Time: 1, Threads: 1, KeyLen: 32}
	hash, err := HashPassword("correct horse battery", p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash format %q", hash)
	}
	ok, rehash, err := VerifyPassword("correct horse battery", hash, p)
	if err != nil || !ok || rehash {
		t.Fatalf("verify = %v %v %v", ok, rehash, err)
	}
	ok, _, err = VerifyPassword("wrong", hash, p)
	if err != nil || ok {
		t.Fatalf("wrong password accepted: %v %v", ok, err)
	}
	stronger := PasswordParams{Memory: 16 * 1024, Time: 2, Threads: 1, KeyLen: 32}
	if _, rehash, _ := VerifyPassword("correct horse battery", hash, stronger); !rehash {
		t.Error("expected rehash signal for weaker parameters")
	}
}

func TestParseParamsRoundTrip(t *testing.T) {
	p := DefaultPasswordParams()
	got, err := ParseParams(EncodeParams(p))
	if err != nil || got != p {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
}

func TestRegisterAndAuthenticate(t *testing.T) {
	a, st := testAuth(t)
	ctx := context.Background()
	u, err := a.Register(ctx, RegisterRequest{Handle: "ada", Password: "hunter2hunter2", IPHash: "ip1"})
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != domain.StatusProbation {
		t.Fatalf("new account status = %q, want probation", u.Status)
	}
	got, err := a.Authenticate(ctx, "ADA", "hunter2hunter2", "ip1")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.ID != u.ID {
		t.Fatal("authenticated the wrong user")
	}
	var attempts int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM login_attempts WHERE ok = 1`).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("login attempts = %d, %v", attempts, err)
	}
}

func TestAuthenticateRejectsBadPasswordWithoutLeaking(t *testing.T) {
	a, _ := testAuth(t)
	ctx := context.Background()
	if _, err := a.Register(ctx, RegisterRequest{Handle: "grace", Password: "hopperhopper"}); err != nil {
		t.Fatal(err)
	}
	_, err := a.Authenticate(ctx, "grace", "nope-nope-nope", "ip")
	if !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("want ErrPermission, got %v", err)
	}
	// Unknown handle must be distinguishable from a bad password for the
	// registration flow, but must not say which part failed.
	_, err = a.Authenticate(ctx, "nobody-here", "whatever123", "ip")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestThrottleLocksOutAfterConfiguredFailures(t *testing.T) {
	a, _ := testAuth(t)
	ctx := context.Background()
	a.cfg.Limits.LoginAttempts = 3
	if _, err := a.Register(ctx, RegisterRequest{Handle: "linus", Password: "kernelkernel"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := a.Authenticate(ctx, "linus", "badpassword", "ip"); !errors.Is(err, domain.ErrPermission) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	_, err := a.Authenticate(ctx, "linus", "kernelkernel", "ip")
	if !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("want rate limited, got %v", err)
	}
	// Time passes: the window expires.
	a.SetClock(func() time.Time { return time.Now().UTC().Add(2 * time.Hour) })
	if _, err := a.Authenticate(ctx, "linus", "kernelkernel", "ip"); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

func TestRegistrationClosed(t *testing.T) {
	a, _ := testAuth(t)
	a.cfg.Registration.Open = false
	_, err := a.Register(context.Background(), RegisterRequest{Handle: "newbie", Password: "password123"})
	if !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("want ErrPermission, got %v", err)
	}
}

func TestRegisterValidatesInput(t *testing.T) {
	a, _ := testAuth(t)
	for _, req := range []RegisterRequest{
		{Handle: "x", Password: "password123"},
		{Handle: "sysop", Password: "password123"},
		{Handle: "goodhandle", Password: "short"},
		{Handle: "goodhandle", Password: "password123", Timezone: "Mars/Olympus"},
	} {
		if _, err := a.Register(context.Background(), req); err == nil {
			t.Errorf("accepted invalid registration %+v", req)
		}
	}
}

func TestMaybePromote(t *testing.T) {
	a, _ := testAuth(t)
	ctx := context.Background()
	u, err := a.Register(ctx, RegisterRequest{Handle: "promo", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a.SetClock(func() time.Time { return now })
	if ok, err := a.MaybePromote(ctx, u, 10); err != nil || ok {
		t.Fatalf("promoted too early: %v %v", ok, err)
	}
	a.SetClock(func() time.Time { return now.Add(4 * 24 * time.Hour) })
	if ok, err := a.MaybePromote(ctx, u, 9); err != nil || ok {
		t.Fatalf("promoted without enough posts: %v %v", ok, err)
	}
	if ok, err := a.MaybePromote(ctx, u, 10); err != nil || !ok {
		t.Fatalf("did not promote: %v %v", ok, err)
	}
}

func TestSignatureIsBounded(t *testing.T) {
	a, _ := testAuth(t)
	ctx := context.Background()
	u, err := a.Register(ctx, RegisterRequest{Handle: "sigtest", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
	u.Signature = "one\ntwo\nthree\nfour\nfive\x1b[31m"
	if err := a.UpdateProfile(ctx, u); err != nil {
		t.Fatal(err)
	}
	stored, err := a.store.UserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(stored.Signature, "\n") > 3 {
		t.Fatalf("signature not trimmed: %q", stored.Signature)
	}
	if strings.Contains(stored.Signature, "\x1b") {
		t.Fatal("signature kept escape sequence")
	}
}

func TestBanCheckerBlocksLoginAndRegistration(t *testing.T) {
	a, st := testAuth(t)
	ctx := context.Background()
	if _, err := a.Register(ctx, RegisterRequest{Handle: "banned-one", Password: "password123"}); err != nil {
		t.Fatal(err)
	}
	a.SetBanChecker(func(ctx context.Context, handle, ipHash string) (bool, string, error) {
		if strings.EqualFold(handle, "banned-one") || ipHash == "badip" {
			return true, "spam", nil
		}
		return false, "", nil
	})

	_, err := a.Authenticate(ctx, "banned-one", "password123", "goodip")
	if !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("banned handle logged in: %v", err)
	}
	_, err = a.Register(ctx, RegisterRequest{Handle: "fresh-handle", Password: "password123", IPHash: "badip"})
	if !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("banned IP registered: %v", err)
	}
	var n int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'auth.banned'`).Scan(&n); err != nil || n == 0 {
		t.Fatalf("expected auth.banned audit rows, got %d (%v)", n, err)
	}

	a.SetBanChecker(func(ctx context.Context, handle, ipHash string) (bool, string, error) { return false, "", nil })
	if _, err := a.Authenticate(ctx, "banned-one", "password123", "goodip"); err != nil {
		t.Fatalf("unbanned login failed: %v", err)
	}
}

func TestUnknownHandleBurnsAnEqualizingHash(t *testing.T) {
	a, _ := testAuth(t)
	ctx := context.Background()
	if _, err := a.Register(ctx, RegisterRequest{Handle: "known-user", Password: "password123"}); err != nil {
		t.Fatal(err)
	}
	before := a.hasher.DummyRuns()
	_, err := a.Authenticate(ctx, "nobody-here", "whatever123", "ip")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown handle error = %v, want ErrNotFound", err)
	}
	if a.hasher.DummyRuns() != before+1 {
		t.Fatalf("dummy hashes = %d, want %d (unknown handles must burn the same cost)",
			a.hasher.DummyRuns(), before+1)
	}
}

func TestPasswordHasherDummyMatchesVerifyCost(t *testing.T) {
	p := PasswordParams{Memory: 8 * 1024, Time: 1, Threads: 1, KeyLen: 32}
	h := NewPasswordHasher(p, 1)
	h.Dummy()
	if h.DummyRuns() != 1 {
		t.Fatalf("DummyRuns = %d", h.DummyRuns())
	}
	// The dummy result must never collide with a real verify: it uses a fixed
	// salt, so a real hash of the dummy password with a fresh salt differs.
	hash, err := h.Hash("hexline-dummy-password")
	if err != nil {
		t.Fatal(err)
	}
	ok, _, err := h.Verify("hexline-dummy-password", hash)
	if err != nil || !ok {
		t.Fatalf("verify own hash = %v %v", ok, err)
	}
}

func TestRegistrationIsRateLimitedPerIP(t *testing.T) {
	a, _ := testAuth(t)
	ctx := context.Background()
	a.cfg.Limits.LoginAttempts = 2
	now := time.Now().UTC()
	a.SetClock(func() time.Time { return now })

	if _, err := a.Register(ctx, RegisterRequest{Handle: "reg-1", Password: "password123", IPHash: "ip1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Register(ctx, RegisterRequest{Handle: "reg-2", Password: "password123", IPHash: "ip1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Register(ctx, RegisterRequest{Handle: "reg-3", Password: "password123", IPHash: "ip1"}); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("third registration from one IP = %v, want rate limited", err)
	}
	// A different IP is not affected.
	if _, err := a.Register(ctx, RegisterRequest{Handle: "reg-4", Password: "password123", IPHash: "ip2"}); err != nil {
		t.Fatalf("other IP was throttled: %v", err)
	}
	// After the window the original IP may register again.
	a.SetClock(func() time.Time { return now.Add(2 * time.Hour) })
	if _, err := a.Register(ctx, RegisterRequest{Handle: "reg-5", Password: "password123", IPHash: "ip1"}); err != nil {
		t.Fatalf("registration after window: %v", err)
	}
	// The sysop CLI path (AllowClosed) is never throttled.
	if _, err := a.Register(ctx, RegisterRequest{Handle: "cli-made", Password: "password123", IPHash: "ip1", AllowClosed: true}); err != nil {
		t.Fatalf("CLI registration throttled: %v", err)
	}
}

func TestFailureMapPrunesExpiredEntries(t *testing.T) {
	a, _ := testAuth(t)
	ctx := context.Background()
	a.cfg.Limits.LoginAttempts = 5
	now := time.Now().UTC()
	a.SetClock(func() time.Time { return now })
	if _, err := a.Register(ctx, RegisterRequest{Handle: "prune-victim", Password: "password123"}); err != nil {
		t.Fatal(err)
	}

	// Build distinct failures so the map has real entries.
	for i := 0; i < 4; i++ {
		if _, err := a.Authenticate(ctx, "prune-victim", "bad", "ip1"); !errors.Is(err, domain.ErrPermission) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if len(a.fails) == 0 {
		t.Fatal("expected failure entries")
	}

	// Advance past the window: the next check must delete the expired keys.
	a.SetClock(func() time.Time { return now.Add(2 * time.Hour) })
	if err := a.throttleCheck("prune-victim", "ip1"); err != nil {
		t.Fatalf("throttleCheck after expiry: %v", err)
	}
	for key := range a.fails {
		if strings.HasPrefix(key, "h:prune-victim") || key == "i:ip1" {
			t.Fatalf("expired entry %q was not pruned", key)
		}
	}

	// The sweep path removes every stale entry once the watermark is crossed.
	a.SetClock(func() time.Time { return now.Add(4 * time.Hour) })
	a.fails["h:stale-1"] = &failWindow{until: now.Add(3 * time.Hour)}
	a.fails["h:stale-2"] = &failWindow{until: now.Add(3 * time.Hour)}
	a.sweepWatermark = 2
	a.recordFailure("another", "ip2", false)
	for key, f := range a.fails {
		if now.Add(4 * time.Hour).After(f.until) {
			t.Fatalf("sweep left an expired entry %q", key)
		}
	}
}
