// Command bbs runs and administers the hexline bulletin board system.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/metrics"
	"github.com/hacktobeer/hexline/internal/service"
	"github.com/hacktobeer/hexline/internal/store"
	sshtransport "github.com/hacktobeer/hexline/internal/transport/ssh"
	"github.com/hacktobeer/hexline/internal/tui"
	"github.com/hacktobeer/hexline/internal/version"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var configPath string
	root := &cobra.Command{
		Use:           "bbs",
		Short:         "hexline — a terminal-first bulletin board system",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&configPath, "config", "hexline.toml", "path to the TOML configuration")

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("hexline", version.String())
		},
	})
	root.AddCommand(serveCmd(&configPath))
	root.AddCommand(migrateCmd(&configPath))
	root.AddCommand(backupCmd(&configPath))
	root.AddCommand(doctorCmd(&configPath))
	root.AddCommand(adminCmd(&configPath))
	return root
}

func loadConfig(path string) (*config.Config, error) {
	return config.LoadOrDefault(path)
}

// runtime holds everything a command needs after config + store are open.
type runtime struct {
	cfg       *config.Config
	store     *store.Store
	auth      *service.Auth
	boards    *service.Boards
	mail      *service.Mail
	files     *service.Files
	community *service.Community
	admin     *service.Admin
	broker    *hub.Broker
	presence  *hub.Presence
	log       *slog.Logger
}

func newRuntime(cfg *config.Config, log *slog.Logger) (*runtime, error) {
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return nil, err
	}
	rt := &runtime{cfg: cfg, store: st, log: log,
		broker: hub.NewBroker(64), presence: hub.NewPresence()}
	rt.auth = service.NewAuth(st, cfg, func(e domain.AuditEntry) {
		if err := st.RecordAudit(e); err != nil {
			log.Warn("audit write failed", "action", e.Action, "err", err)
		}
	})
	rt.auth.SetPasswordParams(service.PasswordParams{
		Memory: cfg.Security.ArgonMemoryKiB, Time: cfg.Security.ArgonTime,
		Threads: cfg.Security.ArgonThreads, KeyLen: 32,
	}, cfg.Security.ArgonConcurrency)
	rt.boards = service.NewBoards(st, cfg)
	rt.mail = service.NewMail(st, cfg)
	rt.files = service.NewFiles(st, cfg)
	rt.community = service.NewCommunity(st, cfg, rt.broker)
	rt.admin = service.NewAdmin(st, cfg, rt.broker)
	// Ban enforcement lives in the admin service but must run before any
	// credential check, so the auth service gets a lookup hook.
	rt.auth.SetBanChecker(rt.admin.IsBanned)
	return rt, nil
}

func (r *runtime) close() {
	if r.store != nil {
		r.store.Close()
	}
}

func serveCmd(configPath *string) *cobra.Command {
	var autoMigrate bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the SSH server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			logger := newLogger()
			tui.EnableColor()
			rt, err := newRuntime(cfg, logger)
			if err != nil {
				return err
			}
			defer rt.close()
			if autoMigrate {
				if err := rt.store.Migrate(); err != nil {
					return err
				}
				if err := rt.store.Seed(); err != nil {
					return err
				}
			}
			n, err := rt.store.CountUsers()
			if err != nil {
				return err
			}
			if n == 0 {
				logger.Warn("no accounts exist yet; create the sysop with: bbs admin user create --handle sysop --role sysop")
			}

			srv, err := sshtransport.New(sshtransport.Deps{
				Cfg: cfg, Store: rt.store, Auth: rt.auth, Boards: rt.boards, Mail: rt.mail,
				Files: rt.files, Community: rt.community, Admin: rt.admin,
				Broker: rt.broker, Presence: rt.presence, Log: logger,
			})
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			startMetrics(ctx, cfg, srv, rt.presence, logger)
			logger.Info("hexline listening",
				"address", cfg.Transport.SSH.Address, "db", cfg.DBPath(),
				"host_key", cfg.HostKeyPath(), "data_dir", cfg.Server.DataDir)
			if err := srv.Serve(ctx); err != nil {
				return err
			}
			logger.Info("hexline stopped")
			return nil
		},
	}
	cmd.Flags().BoolVar(&autoMigrate, "migrate", true, "apply migrations and seed data before serving")
	return cmd
}

func migrateCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Apply database migrations and seed baseline content",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			rt, err := newRuntime(cfg, newLogger())
			if err != nil {
				return err
			}
			defer rt.close()
			if err := rt.store.Migrate(); err != nil {
				return err
			}
			if err := rt.store.Seed(); err != nil {
				return err
			}
			fmt.Println("migrations applied; database at", cfg.DBPath())
			return nil
		},
	}
}

func backupCmd(configPath *string) *cobra.Command {
	var out string
	var keep int
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Write a consistent SQLite snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			if out == "" {
				out = filepath.Join(cfg.Server.DataDir, "backups")
			}
			if err := os.MkdirAll(out, 0o750); err != nil {
				return err
			}
			rt, err := newRuntime(cfg, newLogger())
			if err != nil {
				return err
			}
			defer rt.close()
			target := filepath.Join(out, fmt.Sprintf("hexline-%s.db", time.Now().UTC().Format("20060102-150405")))
			if err := rt.store.Backup(target); err != nil {
				return err
			}
			fmt.Println("backup written:", target)
			if keep > 0 {
				pruned, err := pruneBackups(out, keep)
				if err != nil {
					return err
				}
				if pruned > 0 {
					fmt.Printf("pruned %d old backup(s)\n", pruned)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "directory for snapshots (default <data_dir>/backups)")
	cmd.Flags().IntVar(&keep, "keep", 14, "keep the newest N snapshots (0 disables pruning)")
	return cmd
}

func pruneBackups(dir string, keep int) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "hexline-") && strings.HasSuffix(e.Name(), ".db") {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return 0, nil
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	pruned := 0
	for _, name := range names[keep:] {
		if err := os.Remove(filepath.Join(dir, name)); err == nil {
			pruned++
		}
	}
	return pruned, nil
}

func doctorCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check configuration, database and filesystem health",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			fmt.Println("config:      ok")
			rt, err := newRuntime(cfg, newLogger())
			if err != nil {
				return err
			}
			defer rt.close()
			if err := rt.store.Migrate(); err != nil {
				return err
			}
			integrity, err := rt.store.Integrity()
			if err != nil {
				return err
			}
			fmt.Println("database:   ", integrity, "at", cfg.DBPath())
			if _, err := os.Stat(cfg.HostKeyPath()); err != nil {
				fmt.Println("host key:    missing (created on first serve)")
			} else {
				fmt.Println("host key:    ok")
			}
			for _, dir := range []string{cfg.Server.DataDir, cfg.FilesPath(), filepath.Dir(cfg.DBPath())} {
				if err := os.MkdirAll(dir, 0o750); err != nil {
					return err
				}
			}
			probe := filepath.Join(cfg.FilesPath(), ".write-test")
			if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
				return fmt.Errorf("files dir not writable: %w", err)
			}
			os.Remove(probe)
			fmt.Println("files dir:   writable")
			n, err := rt.store.CountUsers()
			if err != nil {
				return err
			}
			fmt.Printf("accounts:    %d\n", n)
			return nil
		},
	}
}

// startMetrics serves the opt-in metrics/health listener. It is a no-op when
// metrics are disabled.
func startMetrics(ctx context.Context, cfg *config.Config, srv *sshtransport.Server,
	presence *hub.Presence, log *slog.Logger) {
	if !cfg.Metrics.Enabled {
		return
	}
	dbSize := func() int64 {
		var total int64
		for _, p := range []string{cfg.DBPath(), cfg.DBPath() + "-wal"} {
			if fi, err := os.Stat(p); err == nil {
				total += fi.Size()
			}
		}
		return total
	}
	handler := metrics.New(srv.ActiveSessions, srv.TotalSessions, presence.Count, dbSize)
	srvHTTP := &http.Server{
		Addr:              cfg.Metrics.Address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if !isLoopbackAddr(cfg.Metrics.Address) {
		log.Warn("metrics listener is not bound to loopback; restrict access with a firewall",
			"address", cfg.Metrics.Address)
	}
	go func() {
		log.Info("metrics listening", "address", cfg.Metrics.Address)
		if err := srvHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("metrics server stopped", "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srvHTTP.Shutdown(shutdown)
	}()
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	if v, ok := os.LookupEnv("HEXLINE_LOG_LEVEL"); ok {
		switch strings.ToLower(v) {
		case "debug":
			level = slog.LevelDebug
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
	}
	if strings.EqualFold(os.Getenv("HEXLINE_LOG_FORMAT"), "json") {
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
