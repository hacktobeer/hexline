package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/argon2"
)

// PasswordParams are the argon2id cost parameters stored alongside a hash.
// Defaults follow RFC 9106's second recommendation (64 MiB, t=3, p=4).
type PasswordParams struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	KeyLen  uint32
}

// DefaultPasswordParams is the production cost profile.
func DefaultPasswordParams() PasswordParams {
	return PasswordParams{Memory: 64 * 1024, Time: 3, Threads: 4, KeyLen: 32}
}

// LowMemoryPasswordParams is the OWASP minimum, for constrained hosts.
func LowMemoryPasswordParams() PasswordParams {
	return PasswordParams{Memory: 19 * 1024, Time: 2, Threads: 1, KeyLen: 32}
}

const argonVersion = argon2.Version

// HashPassword derives a PHC-formatted argon2id hash with a fresh 128-bit salt.
func HashPassword(password string, p PasswordParams) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVersion, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks password against a PHC string. It returns
// (ok, needsRehash, error); needsRehash is true when the stored parameters are
// weaker than want.
func VerifyPassword(password, phc string, want PasswordParams) (bool, bool, error) {
	mem, iters, threads, salt, hash, err := parsePHC(phc)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(password), salt, iters, mem, threads, uint32(len(hash)))
	ok := subtle.ConstantTimeCompare(got, hash) == 1
	weaker := mem < want.Memory || iters < want.Time || threads < want.Threads
	return ok, ok && weaker, nil
}

func parsePHC(phc string) (mem, iters uint32, threads uint8, salt, hash []byte, err error) {
	parts := strings.Split(strings.TrimSpace(phc), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("password: unsupported hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argonVersion {
		return 0, 0, 0, nil, nil, errors.New("password: unsupported argon2 version")
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return 0, 0, 0, nil, nil, errors.New("password: malformed params")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return 0, 0, 0, nil, nil, errors.New("password: malformed salt")
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 {
		return 0, 0, 0, nil, nil, errors.New("password: malformed hash")
	}
	if m == 0 || t == 0 || p == 0 {
		return 0, 0, 0, nil, nil, errors.New("password: zero cost parameters")
	}
	return m, t, p, salt, hash, nil
}

// PasswordHasher serializes expensive hashes so a login burst cannot exhaust
// memory (64 MiB per concurrent argon2 call).
type PasswordHasher struct {
	params    PasswordParams
	sem       chan struct{}
	dummyRuns atomic.Int64
}

// NewPasswordHasher returns a hasher with at most n concurrent derivations.
func NewPasswordHasher(params PasswordParams, n int) *PasswordHasher {
	if n < 1 {
		n = 1
	}
	return &PasswordHasher{params: params, sem: make(chan struct{}, n)}
}

// Params exposes the configured cost profile.
func (h *PasswordHasher) Params() PasswordParams { return h.params }

// Hash derives a hash, blocking while at capacity.
func (h *PasswordHasher) Hash(password string) (string, error) {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	return HashPassword(password, h.params)
}

// dummySalt is a fixed salt used only for equalizing timing on unknown
// handles. It never corresponds to a stored hash.
var dummySalt = [16]byte{
	0x68, 0x65, 0x78, 0x6c, 0x69, 0x6e, 0x65, 0x2d,
	0x64, 0x75, 0x6d, 0x6d, 0x79, 0x2d, 0x73, 0x61,
}

// Dummy performs an argon2id derivation of identical cost to a real verify,
// with a fixed salt. Login calls it for unknown handles so the wall-clock
// time does not reveal whether a handle exists.
func (h *PasswordHasher) Dummy() {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	_ = argon2.IDKey([]byte("hexline-dummy-password"), dummySalt[:],
		h.params.Time, h.params.Memory, h.params.Threads, h.params.KeyLen)
	h.dummyRuns.Add(1)
}

// DummyRuns reports how many equalizing hashes have been performed.
func (h *PasswordHasher) DummyRuns() int64 { return h.dummyRuns.Load() }

// Verify checks a password, returning whether the stored hash should be
// upgraded to the current parameters.
func (h *PasswordHasher) Verify(password, phc string) (ok, rehash bool, err error) {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	return VerifyPassword(password, phc, h.params)
}
