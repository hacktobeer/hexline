// Package config loads and validates hexline's TOML configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the root configuration document.
type Config struct {
	Server       Server       `toml:"server"`
	Transport    Transport    `toml:"transport"`
	Database     Database     `toml:"database"`
	Storage      Storage      `toml:"storage"`
	Limits       Limits       `toml:"limits"`
	Retention    Retention    `toml:"retention"`
	Metrics      Metrics      `toml:"metrics"`
	UI           UI           `toml:"ui"`
	Probation    Probation    `toml:"probation"`
	Registration Registration `toml:"registration"`
	Security     Security     `toml:"security"`
}

// Server holds process-wide settings.
type Server struct {
	Name string `toml:"name"`
	// DataDir is the root for the database, host key, uploads and art.
	DataDir string `toml:"data_dir"`
}

// Transport holds network listener settings. SSH is the only transport (D1).
type Transport struct {
	SSH SSH `toml:"ssh"`
}

// SSH configures the single SSH listener.
type SSH struct {
	Address     string        `toml:"address"`
	HostKeyPath string        `toml:"host_key_path"`
	MaxSessions int           `toml:"max_sessions"`
	MaxPerIP    int           `toml:"max_per_ip"`
	IdleTimeout time.Duration `toml:"idle_timeout"`
	AllowPubkey bool          `toml:"allow_pubkey"`
	BannerText  string        `toml:"banner_text"`
}

// Database configures the SQLite store.
type Database struct {
	Path string `toml:"path"`
}

// Storage configures uploads and generated files.
type Storage struct {
	FilesDir       string   `toml:"files_dir"`
	MaxUploadBytes int64    `toml:"max_upload_bytes"`
	AllowedExt     []string `toml:"allowed_ext"`
}

// Limits configures abuse controls.
type Limits struct {
	PostMaxBytes      int           `toml:"post_max_bytes"`
	PostRatePerHour   int           `toml:"post_rate_per_hour"`
	MailQuota         int           `toml:"mail_quota"`
	UploadQuotaBytes  int64         `toml:"upload_quota_bytes"`
	LoginAttempts     int           `toml:"login_attempts"`
	LoginWindow       time.Duration `toml:"login_window"`
	ChatRatePerMinute int           `toml:"chat_rate_per_minute"`
	MaxBodyLines      int           `toml:"max_body_lines"`
	MaxSignatureLines int           `toml:"max_signature_lines"`
}

// Retention configures pruning. Zero disables a prune.
type Retention struct {
	SessionsDays     int `toml:"sessions_days"`
	AuditDays        int `toml:"audit_days"`
	OnelinerDays     int `toml:"oneliner_days"`
	DeletedPostsDays int `toml:"deleted_posts_days"`
}

// Metrics configures the optional loopback HTTP listener.
type Metrics struct {
	Enabled bool   `toml:"enabled"`
	Address string `toml:"address"`
}

// UI configures presentation defaults.
type UI struct {
	ServerName   string `toml:"server_name"`
	DefaultWidth int    `toml:"default_width"`
	DefaultRows  int    `toml:"default_rows"`
	MOTD         string `toml:"motd"`
}

// Probation configures new-user limits (D9).
type Probation struct {
	Days  int `toml:"days"`
	Posts int `toml:"posts"`
}

// Security tunes credential hashing. Argon2id is memory-hard; the concurrency
// cap bounds peak memory at ArgonConcurrency * ArgonMemoryKiB.
type Security struct {
	ArgonMemoryKiB   uint32 `toml:"argon_memory_kib"`
	ArgonTime        uint32 `toml:"argon_time"`
	ArgonThreads     uint8  `toml:"argon_threads"`
	ArgonConcurrency int    `toml:"argon_concurrency"`
}

// Registration configures account creation (D3).
type Registration struct {
	Open bool `toml:"open"`
}

// Default returns the built-in defaults for a fresh install.
func Default() *Config {
	return &Config{
		Server: Server{Name: "hexline", DataDir: "./data"},
		Transport: Transport{SSH: SSH{
			Address:     ":2222",
			HostKeyPath: "host_ed25519",
			MaxSessions: 200,
			MaxPerIP:    8,
			IdleTimeout: 15 * time.Minute,
			AllowPubkey: true,
			BannerText:  "hexline BBS",
		}},
		Database: Database{Path: "hexline.db"},
		Storage: Storage{
			FilesDir:       "files",
			MaxUploadBytes: 64 << 20,
		},
		Limits: Limits{
			PostMaxBytes:      32 << 10,
			PostRatePerHour:   30,
			MailQuota:         200,
			UploadQuotaBytes:  512 << 20,
			LoginAttempts:     10,
			LoginWindow:       15 * time.Minute,
			ChatRatePerMinute: 30,
			MaxBodyLines:      1000,
			MaxSignatureLines: 4,
		},
		Retention:    Retention{SessionsDays: 90, AuditDays: 365, OnelinerDays: 30, DeletedPostsDays: 30},
		Metrics:      Metrics{Enabled: false, Address: "127.0.0.1:9101"},
		UI:           UI{ServerName: "hexline", DefaultWidth: 80, DefaultRows: 24},
		Probation:    Probation{Days: 3, Posts: 10},
		Registration: Registration{Open: true},
		Security: Security{
			ArgonMemoryKiB: 32 * 1024, ArgonTime: 3, ArgonThreads: 2, ArgonConcurrency: 2,
		},
	}
}

// Load reads path (missing file is an error), applies HEXLINE_* environment
// overrides, then validates.
func Load(path string) (*Config, error) {
	cfg := Default()
	if err := decodeFile(path, cfg); err != nil {
		return nil, err
	}
	applyEnv(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func decodeFile(path string, cfg *Config) error {
	md, err := toml.DecodeFile(path, cfg)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config %s: file not found", path)
		}
		return fmt.Errorf("config %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return fmt.Errorf("config %s: unknown keys: %v", path, undecoded)
	}
	return nil
}

// LoadOrDefault loads path when it exists, otherwise uses defaults. In both
// cases HEXLINE_* environment overrides are applied and validated.
func LoadOrDefault(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			if err := decodeFile(path, cfg); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	applyEnv(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyEnv(c *Config) {
	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv(key); ok {
			*dst = v
		}
	}
	num := func(key string, dst *int) {
		if v, ok := os.LookupEnv(key); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				*dst = n
			}
		}
	}
	num64 := func(key string, dst *int64) {
		if v, ok := os.LookupEnv(key); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				*dst = n
			}
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := os.LookupEnv(key); ok {
			if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
				*dst = b
			}
		}
	}
	dur := func(key string, dst *time.Duration) {
		if v, ok := os.LookupEnv(key); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
				*dst = d
			}
		}
	}
	str("HEXLINE_DATA_DIR", &c.Server.DataDir)
	str("HEXLINE_SSH_ADDRESS", &c.Transport.SSH.Address)
	str("HEXLINE_SSH_HOST_KEY", &c.Transport.SSH.HostKeyPath)
	str("HEXLINE_DB_PATH", &c.Database.Path)
	str("HEXLINE_FILES_DIR", &c.Storage.FilesDir)
	str("HEXLINE_METRICS_ADDR", &c.Metrics.Address)
	num("HEXLINE_SSH_MAX_SESSIONS", &c.Transport.SSH.MaxSessions)
	num("HEXLINE_SSH_MAX_PER_IP", &c.Transport.SSH.MaxPerIP)
	dur("HEXLINE_SSH_IDLE_TIMEOUT", &c.Transport.SSH.IdleTimeout)
	boolean("HEXLINE_SSH_PUBKEY", &c.Transport.SSH.AllowPubkey)
	num64("HEXLINE_MAX_UPLOAD_BYTES", &c.Storage.MaxUploadBytes)
	boolean("HEXLINE_METRICS", &c.Metrics.Enabled)
	boolean("HEXLINE_REGISTRATION_OPEN", &c.Registration.Open)
	num("HEXLINE_PROBATION_DAYS", &c.Probation.Days)
	num("HEXLINE_PROBATION_POSTS", &c.Probation.Posts)
	if v, ok := os.LookupEnv("HEXLINE_ARGON_MEMORY_KIB"); ok {
		if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32); err == nil {
			c.Security.ArgonMemoryKiB = uint32(n)
		}
	}
	num("HEXLINE_ARGON_CONCURRENCY", &c.Security.ArgonConcurrency)
}

// Validate returns actionable, key-scoped errors.
func (c *Config) Validate() error {
	var errs []string
	if strings.TrimSpace(c.Server.DataDir) == "" {
		errs = append(errs, "server.data_dir: must not be empty")
	}
	if strings.TrimSpace(c.Transport.SSH.Address) == "" {
		errs = append(errs, "transport.ssh.address: must not be empty (e.g. \":2222\")")
	}
	if !strings.Contains(c.Transport.SSH.Address, ":") {
		errs = append(errs, "transport.ssh.address: must be host:port")
	}
	if c.Transport.SSH.MaxSessions < 1 {
		errs = append(errs, "transport.ssh.max_sessions: must be >= 1")
	}
	if c.Transport.SSH.MaxPerIP < 1 {
		errs = append(errs, "transport.ssh.max_per_ip: must be >= 1")
	}
	if c.Transport.SSH.IdleTimeout <= 0 {
		errs = append(errs, "transport.ssh.idle_timeout: must be > 0 (e.g. \"15m\")")
	}
	if strings.TrimSpace(c.Database.Path) == "" {
		errs = append(errs, "database.path: must not be empty")
	}
	if c.Storage.MaxUploadBytes < 1 {
		errs = append(errs, "storage.max_upload_bytes: must be >= 1")
	}
	if c.Limits.PostMaxBytes < 1024 {
		errs = append(errs, "limits.post_max_bytes: must be >= 1024")
	}
	if c.Limits.PostRatePerHour < 1 {
		errs = append(errs, "limits.post_rate_per_hour: must be >= 1")
	}
	if c.Limits.LoginAttempts < 1 {
		errs = append(errs, "limits.login_attempts: must be >= 1")
	}
	if c.Limits.LoginWindow <= 0 {
		errs = append(errs, "limits.login_window: must be > 0")
	}
	if c.Security.ArgonMemoryKiB < 8*1024 {
		errs = append(errs, "security.argon_memory_kib: must be at least 8192 (8 MiB)")
	}
	if c.Security.ArgonTime < 1 {
		errs = append(errs, "security.argon_time: must be >= 1")
	}
	if c.Security.ArgonThreads < 1 {
		errs = append(errs, "security.argon_threads: must be >= 1")
	}
	if c.Security.ArgonConcurrency < 1 {
		errs = append(errs, "security.argon_concurrency: must be >= 1")
	}
	if c.Probation.Days < 0 || c.Probation.Posts < 0 {
		errs = append(errs, "probation.days/probation.posts: must be >= 0")
	}
	if c.UI.DefaultWidth < 40 || c.UI.DefaultWidth > 400 {
		errs = append(errs, "ui.default_width: must be between 40 and 400")
	}
	if c.Metrics.Enabled && strings.TrimSpace(c.Metrics.Address) == "" {
		errs = append(errs, "metrics.address: required when metrics.enabled = true")
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// AbsPath resolves p against the data dir unless it is already absolute.
func (c *Config) AbsPath(p string) string {
	if p == "" {
		return c.Server.DataDir
	}
	if strings.HasPrefix(p, "/") {
		return p
	}
	return c.Server.DataDir + "/" + p
}

// DBPath is the absolute SQLite path.
func (c *Config) DBPath() string { return c.AbsPath(c.Database.Path) }

// HostKeyPath is the absolute SSH host key path.
func (c *Config) HostKeyPath() string { return c.AbsPath(c.Transport.SSH.HostKeyPath) }

// FilesPath is the absolute upload root.
func (c *Config) FilesPath() string { return c.AbsPath(c.Storage.FilesDir) }
