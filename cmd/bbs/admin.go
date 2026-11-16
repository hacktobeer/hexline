package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"

	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/service"
	sshtransport "github.com/hacktobeer/hexline/internal/transport/ssh"
)

// adminCmd is the sysop CLI.
func adminCmd(configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Sysop commands (users, areas, bulletins, backups, audit)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(adminUserCmd(configPath))
	cmd.AddCommand(adminAreaCmd(configPath))
	cmd.AddCommand(adminFileAreaCmd(configPath))
	cmd.AddCommand(adminBulletinCmd(configPath))
	cmd.AddCommand(adminPollCmd(configPath))
	cmd.AddCommand(adminBanCmd(configPath))
	cmd.AddCommand(adminAuditCmd(configPath))
	cmd.AddCommand(adminStatsCmd(configPath))
	cmd.AddCommand(adminPruneCmd(configPath))
	cmd.AddCommand(adminBroadcastCmd(configPath))
	return cmd
}

// adminWithRuntime opens the configured store exactly like serve does, applies
// migrations and closes everything when the command finishes.
func adminWithRuntime(configPath string, fn func(*runtime) error) error {
	cfg, err := loadConfig(configPath)
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
	return fn(rt)
}

func cliAdminActor() *domain.User {
	return &domain.User{ID: "cli", Handle: "cli", Role: domain.RoleSysop, Status: domain.StatusActive}
}

func cliAdminContext() context.Context {
	return service.WithAdminActor(context.Background(), cliAdminActor())
}

// cliSysopActor resolves a real account for rows with a users(id) foreign key
// (polls.created_by). The synthetic CLI actor is not an account.
func cliSysopActor(rt *runtime) (*domain.User, error) {
	users, err := rt.store.ListUsers(1000, 0)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].Role == domain.RoleSysop && users[i].Status != domain.StatusDeleted {
			u := users[i]
			return &u, nil
		}
	}
	return nil, errors.New("no sysop account exists; create one with: bbs admin user create --handle sysop --role sysop")
}

func adminTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
}

// parseAdminTime accepts empty (never), RFC3339, a date, or a relative duration
// such as "24h" or "720h".
func parseAdminTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02 15:04", value); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t.UTC(), nil
	}
	if d, err := time.ParseDuration(value); err == nil {
		return time.Now().UTC().Add(d), nil
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q (use RFC3339, YYYY-MM-DD, or a duration like 24h)", value)
}

// --- area ---

func adminAreaCmd(configPath *string) *cobra.Command {
	area := &cobra.Command{
		Use:   "area",
		Short: "Manage message areas",
		RunE:  func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List message areas",
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				areas, err := rt.store.AdminListAreas()
				if err != nil {
					return err
				}
				tw := adminTabWriter()
				fmt.Fprintln(tw, "TAG\tNAME\tSORT\tREAD\tPOST\tMODERATE\tRETENTION\tRATE/H")
				for _, a := range areas {
					fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%d\t%d\n",
						a.Tag, a.Name, a.SortOrder,
						domain.FormatACL(a.ACL.Read), domain.FormatACL(a.ACL.Post),
						domain.FormatACL(a.ACL.Moderate), a.RetentionDays, a.RateLimitPerHour)
				}
				return tw.Flush()
			})
		},
	}

	var tag, name, description, aclRead, aclPost, aclModerate string
	var sortOrder int
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a message area",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(tag) == "" {
				return errors.New("--tag is required")
			}
			if strings.TrimSpace(name) == "" {
				return errors.New("--name is required")
			}
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				a, err := rt.admin.CreateArea(context.Background(), cliAdminActor(),
					tag, name, description, sortOrder, aclRead, aclPost, aclModerate)
				if err != nil {
					return err
				}
				fmt.Printf("created area %s (%s)\n", a.Tag, a.ID)
				return nil
			})
		},
	}
	create.Flags().StringVar(&tag, "tag", "", "area tag (lowercase letters, digits, dashes)")
	create.Flags().StringVar(&name, "name", "", "display name")
	create.Flags().StringVar(&description, "description", "", "one-line description")
	create.Flags().IntVar(&sortOrder, "sort", 10, "display order")
	create.Flags().StringVar(&aclRead, "acl-read", "user", "roles allowed to read")
	create.Flags().StringVar(&aclPost, "acl-post", "user", "roles allowed to post")
	create.Flags().StringVar(&aclModerate, "acl-moderate", "moderator", "roles allowed to moderate")

	var eName, eDescription, eACLRead, eACLPost, eACLModerate string
	var eSort, eRetention, eRate int
	edit := &cobra.Command{
		Use:   "edit TAG",
		Short: "Edit a message area (tag is immutable)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				current, err := rt.store.AdminAreaByTag(args[0])
				if err != nil {
					return err
				}
				name := current.Name
				if cmd.Flags().Changed("name") {
					name = eName
				}
				description := current.Description
				if cmd.Flags().Changed("description") {
					description = eDescription
				}
				sortOrder := current.SortOrder
				if cmd.Flags().Changed("sort") {
					sortOrder = eSort
				}
				read := domain.FormatACL(current.ACL.Read)
				if cmd.Flags().Changed("acl-read") {
					read = eACLRead
				}
				post := domain.FormatACL(current.ACL.Post)
				if cmd.Flags().Changed("acl-post") {
					post = eACLPost
				}
				mod := domain.FormatACL(current.ACL.Moderate)
				if cmd.Flags().Changed("acl-moderate") {
					mod = eACLModerate
				}
				retention := current.RetentionDays
				if cmd.Flags().Changed("retention") {
					retention = eRetention
				}
				rate := current.RateLimitPerHour
				if cmd.Flags().Changed("rate") {
					rate = eRate
				}
				if err := rt.admin.UpdateArea(context.Background(), cliAdminActor(), current.ID,
					name, description, sortOrder, read, post, mod, retention, rate); err != nil {
					return err
				}
				fmt.Printf("updated area %s\n", current.Tag)
				return nil
			})
		},
	}
	edit.Flags().StringVar(&eName, "name", "", "display name")
	edit.Flags().StringVar(&eDescription, "description", "", "one-line description")
	edit.Flags().IntVar(&eSort, "sort", 0, "display order")
	edit.Flags().StringVar(&eACLRead, "acl-read", "", "roles allowed to read")
	edit.Flags().StringVar(&eACLPost, "acl-post", "", "roles allowed to post")
	edit.Flags().StringVar(&eACLModerate, "acl-moderate", "", "roles allowed to moderate")
	edit.Flags().IntVar(&eRetention, "retention", 0, "retention in days (0 keeps posts)")
	edit.Flags().IntVar(&eRate, "rate", 0, "posts per hour cap (0 unlimited)")

	var force bool
	del := &cobra.Command{
		Use:   "delete TAG",
		Short: "Delete a message area",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				current, err := rt.store.AdminAreaByTag(args[0])
				if err != nil {
					return err
				}
				if err := rt.admin.DeleteArea(context.Background(), cliAdminActor(), current.ID, force); err != nil {
					return err
				}
				fmt.Printf("deleted area %s\n", current.Tag)
				return nil
			})
		},
	}
	del.Flags().BoolVar(&force, "force", false, "delete even when threads exist")

	area.AddCommand(list, create, edit, del)
	return area
}

// --- file areas ---

func adminFileAreaCmd(configPath *string) *cobra.Command {
	fa := &cobra.Command{
		Use:   "filearea",
		Short: "Manage file areas",
		RunE:  func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List file areas",
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				areas, err := rt.store.ListFileAreas()
				if err != nil {
					return err
				}
				tw := adminTabWriter()
				fmt.Fprintln(tw, "TAG\tNAME\tSORT\tREAD\tUPLOAD\tQUOTA")
				for _, a := range areas {
					fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%d\n", a.Tag, a.Name, a.SortOrder,
						domain.FormatACL(a.ACL.Read), domain.FormatACL(a.ACL.Post), a.QuotaBytes)
				}
				return tw.Flush()
			})
		},
	}

	var tag, name, description, aclRead, aclUpload string
	var sortOrder int
	var quota int64
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a file area",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(tag) == "" {
				return errors.New("--tag is required")
			}
			if strings.TrimSpace(name) == "" {
				return errors.New("--name is required")
			}
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				a, err := rt.admin.CreateFileArea(context.Background(), cliAdminActor(),
					tag, name, description, sortOrder, aclRead, aclUpload, quota)
				if err != nil {
					return err
				}
				fmt.Printf("created file area %s (%s)\n", a.Tag, a.ID)
				return nil
			})
		},
	}
	create.Flags().StringVar(&tag, "tag", "", "file area tag")
	create.Flags().StringVar(&name, "name", "", "display name")
	create.Flags().StringVar(&description, "description", "", "one-line description")
	create.Flags().IntVar(&sortOrder, "sort", 10, "display order")
	create.Flags().StringVar(&aclRead, "acl-read", "user", "roles allowed to download")
	create.Flags().StringVar(&aclUpload, "acl-upload", "user", "roles allowed to upload")
	create.Flags().Int64Var(&quota, "quota", 0, "area quota in bytes (0 unlimited)")

	fa.AddCommand(list, create)
	return fa
}

// --- bulletins ---

func adminBulletinCmd(configPath *string) *cobra.Command {
	b := &cobra.Command{
		Use:   "bulletin",
		Short: "Manage bulletins / MOTD notices",
		RunE:  func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List bulletins",
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				items, err := rt.community.Bulletins(context.Background(), nil)
				if err != nil {
					return err
				}
				tw := adminTabWriter()
				fmt.Fprintln(tw, "ID\tSORT\tACTIVE\tUPDATED\tTITLE")
				for _, item := range items {
					fmt.Fprintf(tw, "%s\t%d\t%t\t%s\t%s\n", item.ID, item.Sort, item.Active,
						item.UpdatedAt.Format("2006-01-02"), item.Title)
				}
				return tw.Flush()
			})
		},
	}

	var title, body string
	var sortOrder int
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a bulletin",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(title) == "" {
				return errors.New("--title is required")
			}
			if strings.TrimSpace(body) == "" {
				return errors.New("--body is required")
			}
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				item, err := rt.community.CreateBulletin(context.Background(), cliAdminActor(), title, body, sortOrder)
				if err != nil {
					return err
				}
				fmt.Printf("created bulletin %s\n", item.ID)
				return nil
			})
		},
	}
	create.Flags().StringVar(&title, "title", "", "bulletin title")
	create.Flags().StringVar(&body, "body", "", "bulletin body (plain text)")
	create.Flags().IntVar(&sortOrder, "sort", 10, "display order")

	del := &cobra.Command{
		Use:   "delete ID",
		Short: "Delete a bulletin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				if err := rt.community.DeleteBulletin(context.Background(), cliAdminActor(), args[0]); err != nil {
					return err
				}
				fmt.Printf("deleted bulletin %s\n", args[0])
				return nil
			})
		},
	}
	b.AddCommand(list, create, del)
	return b
}

// --- polls ---

func adminPollCmd(configPath *string) *cobra.Command {
	poll := &cobra.Command{
		Use:   "poll",
		Short: "Manage polls",
		RunE:  func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	var question, closes string
	var options []string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a single-choice poll",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(question) == "" {
				return errors.New("--question is required")
			}
			if len(options) < 2 {
				return errors.New("at least two --option flags are required")
			}
			closesAt, err := parseAdminTime(closes)
			if err != nil {
				return err
			}
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				actor, err := cliSysopActor(rt)
				if err != nil {
					return err
				}
				p, err := rt.community.CreatePoll(context.Background(), actor, question, options, closesAt)
				if err != nil {
					return err
				}
				fmt.Printf("created poll %s with %d options\n", p.ID, len(p.Options))
				return nil
			})
		},
	}
	create.Flags().StringVar(&question, "question", "", "poll question")
	create.Flags().StringArrayVar(&options, "option", nil, "poll option (repeatable, at least two)")
	create.Flags().StringVar(&closes, "closes", "", "close time (RFC3339, date, or duration)")

	poll.AddCommand(create)
	return poll
}

// --- bans ---

func adminBanCmd(configPath *string) *cobra.Command {
	ban := &cobra.Command{
		Use:   "ban",
		Short: "Manage handle and IP bans",
		RunE:  func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}

	var scope, value, reason, expires string
	add := &cobra.Command{
		Use:   "add",
		Short: "Ban a handle or IP hash",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(value) == "" {
				return errors.New("--value is required")
			}
			expiresAt, err := parseAdminTime(expires)
			if err != nil {
				return err
			}
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				b, err := rt.admin.SetBan(context.Background(), cliAdminActor(), scope, value, reason, expiresAt)
				if err != nil {
					return err
				}
				fmt.Printf("banned %s %s (%s)\n", b.Scope, b.Value, b.ID)
				return nil
			})
		},
	}
	add.Flags().StringVar(&scope, "scope", "handle", "handle, or ip (requires the 22-char ip_hash from the audit log)")
	add.Flags().StringVar(&value, "value", "", "handle, or the 22-char HMAC ip_hash (raw IPs never match)")
	add.Flags().StringVar(&reason, "reason", "", "why the ban was applied")
	add.Flags().StringVar(&expires, "expires", "", "expiry (RFC3339, date, or duration; empty = permanent)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List bans",
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				bans, err := rt.admin.ListBans(context.Background())
				if err != nil {
					return err
				}
				tw := adminTabWriter()
				fmt.Fprintln(tw, "ID\tSCOPE\tVALUE\tREASON\tEXPIRES\tCREATED_BY")
				for _, b := range bans {
					exp := "never"
					if !b.ExpiresAt.IsZero() {
						exp = b.ExpiresAt.Format(time.RFC3339)
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
						b.ID, b.Scope, b.Value, b.Reason, exp, b.CreatedBy)
				}
				return tw.Flush()
			})
		},
	}

	remove := &cobra.Command{
		Use:   "remove ID",
		Short: "Lift a ban",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				if err := rt.admin.RemoveBan(context.Background(), cliAdminActor(), args[0]); err != nil {
					return err
				}
				fmt.Printf("removed ban %s\n", args[0])
				return nil
			})
		},
	}
	ban.AddCommand(add, list, remove)
	return ban
}

// --- audit, stats, prune, broadcast ---

func adminAuditCmd(configPath *string) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log tail",
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 {
				return errors.New("--limit must be at least 1")
			}
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				entries, err := rt.admin.ListAudit(context.Background(), limit)
				if err != nil {
					return err
				}
				tw := adminTabWriter()
				fmt.Fprintln(tw, "AT\tACTOR\tACTION\tTARGET\tDETAIL")
				for _, e := range entries {
					actor := e.Actor
					if actor == "" {
						actor = "system"
					}
					target := e.TargetKind
					if e.TargetID != "" {
						target += ":" + e.TargetID
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
						e.At.UTC().Format("2006-01-02 15:04:05"), actor, e.Action, target, e.Detail)
				}
				return tw.Flush()
			})
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "number of entries")
	return cmd
}

func adminStatsCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show board counters",
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				s, err := rt.admin.Stats(context.Background())
				if err != nil {
					return err
				}
				tw := adminTabWriter()
				fmt.Fprintln(tw, "METRIC\tVALUE")
				rows := [][2]string{
					{"users", fmt.Sprint(s.Users)},
					{"active", fmt.Sprint(s.Active)},
					{"probation", fmt.Sprint(s.Probation)},
					{"suspended", fmt.Sprint(s.Suspended)},
					{"areas", fmt.Sprint(s.Areas)},
					{"threads", fmt.Sprint(s.Threads)},
					{"posts", fmt.Sprint(s.Posts)},
					{"file_areas", fmt.Sprint(s.FileAreas)},
					{"files", fmt.Sprint(s.Files)},
					{"mail", fmt.Sprint(s.Mail)},
					{"oneliners", fmt.Sprint(s.Oneliners)},
					{"sessions_24h", fmt.Sprint(s.Sessions24h)},
					{"db_bytes", fmt.Sprint(s.DBBytes)},
				}
				for _, row := range rows {
					fmt.Fprintf(tw, "%s\t%s\n", row[0], row[1])
				}
				return tw.Flush()
			})
		},
	}
}

func adminPruneCmd(configPath *string) *cobra.Command {
	var apply bool
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Report what retention would delete (add --yes to delete)",
		RunE: func(cmd *cobra.Command, args []string) error {
			dryRun := !apply
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				res, err := rt.admin.Prune(cliAdminContext(), dryRun)
				if err != nil {
					return err
				}
				if dryRun {
					fmt.Println("dry run — nothing deleted")
				}
				tw := adminTabWriter()
				fmt.Fprintln(tw, "CATEGORY\tROWS")
				fmt.Fprintf(tw, "sessions\t%d\n", res.Sessions)
				fmt.Fprintf(tw, "audit\t%d\n", res.Audit)
				fmt.Fprintf(tw, "oneliners\t%d\n", res.Oneliners)
				fmt.Fprintf(tw, "deleted_posts\t%d\n", res.DeletedPosts)
				return tw.Flush()
			})
		},
	}
	cmd.Flags().BoolVar(&apply, "yes", false, "actually delete; without it prune only reports counts")
	return cmd
}

func adminBroadcastCmd(configPath *string) *cobra.Command {
	var text string
	cmd := &cobra.Command{
		Use:   "broadcast",
		Short: "Publish a notice to every connected session",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(text) == "" {
				return errors.New("--text is required")
			}
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				if err := rt.admin.Broadcast(context.Background(), cliAdminActor(), text); err != nil {
					return err
				}
				fmt.Println("broadcast published")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&text, "text", "", "notice text")
	return cmd
}

func adminUserCmd(configPath *string) *cobra.Command {
	user := &cobra.Command{
		Use:   "user",
		Short: "Manage accounts",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	var handle, role, password, passwordFile, realName string
	create := &cobra.Command{
		Use:   "create",
		Short: "Create an account (prints a generated password when omitted)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if handle == "" {
				return errors.New("--handle is required")
			}
			if err := domain.ValidateHandleShape(handle); err != nil {
				return err
			}
			r := domain.Role(role)
			if !r.Valid() {
				return fmt.Errorf("unknown role %q (user, moderator, sysop)", role)
			}
			password, generated, err := adminResolvePassword(password, passwordFile)
			if err != nil {
				return err
			}
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
			u, err := rt.auth.Register(context.Background(), service.RegisterRequest{
				Handle: handle, Password: password, RealName: realName,
				AllowClosed: true, AllowReserved: domain.Role(role) == domain.RoleSysop,
			})
			if err != nil {
				return err
			}
			// Accounts created by the sysop start active, not on probation.
			if err := rt.store.SetStatus(u.ID, domain.StatusActive); err != nil {
				return err
			}
			if err := rt.store.SetRole(u.ID, r); err != nil {
				return err
			}
			if err := rt.store.RecordAudit(domain.AuditEntry{
				Actor: "cli", Action: "user.create", TargetKind: "user", TargetID: u.ID,
				Detail: fmt.Sprintf(`{"handle":%q,"role":%q}`, u.Handle, r),
			}); err != nil {
				return err
			}
			fmt.Printf("created %s with role %s\n", u.Handle, r)
			if generated {
				fmt.Printf("password: %s\n", password)
			}
			return nil
		},
	}
	create.Flags().StringVar(&handle, "handle", "", "account handle")
	create.Flags().StringVar(&role, "role", "user", "user, moderator or sysop")
	create.Flags().StringVar(&password, "password", "", "password (generated when empty; visible in shell history)")
	create.Flags().StringVar(&passwordFile, "password-file", "", "read the password from this file instead of the command line")
	create.Flags().StringVar(&realName, "name", "", "real name (optional)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List accounts",
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
			users, err := rt.store.ListUsers(500, 0)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "HANDLE\tROLE\tSTATUS\tCALLS\tCREATED")
			for _, u := range users {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", u.Handle, u.Role, u.Status, u.Calls, u.CreatedAt.Format("2006-01-02"))
			}
			return tw.Flush()
		},
	}

	var newRole string
	setRole := &cobra.Command{
		Use:   "role HANDLE",
		Short: "Change an account role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := domain.Role(newRole)
			if !r.Valid() {
				return fmt.Errorf("unknown role %q", newRole)
			}
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
			u, err := rt.store.UserByHandle(args[0])
			if err != nil {
				return err
			}
			if err := rt.admin.SetUserRole(context.Background(), cliAdminActor(), u.ID, r); err != nil {
				return err
			}
			fmt.Printf("%s is now %s\n", u.Handle, r)
			return nil
		},
	}
	setRole.Flags().StringVar(&newRole, "role", "", "user, moderator or sysop")

	promote := &cobra.Command{
		Use:   "promote HANDLE",
		Short: "Turn a probationary account into a full account",
		Args:  cobra.ExactArgs(1),
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
			u, err := rt.store.UserByHandle(args[0])
			if err != nil {
				return err
			}
			if err := rt.auth.Promote(context.Background(), cliAdminActor(), u.ID); err != nil {
				return err
			}
			fmt.Printf("%s is now active\n", u.Handle)
			return nil
		},
	}

	var newPassword, pwFile string
	passwd := &cobra.Command{
		Use:   "passwd HANDLE",
		Short: "Reset an account password",
		Args:  cobra.ExactArgs(1),
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
			newPassword, _, err = adminResolvePassword(newPassword, pwFile)
			if err != nil {
				return err
			}
			if err := rt.auth.ResetPassword(context.Background(), args[0], newPassword); err != nil {
				return err
			}
			fmt.Printf("password for %s: %s\n", args[0], newPassword)
			return nil
		},
	}
	passwd.Flags().StringVar(&newPassword, "password", "", "new password (generated when empty; visible in shell history)")
	passwd.Flags().StringVar(&pwFile, "password-file", "", "read the new password from this file instead of the command line")

	status := &cobra.Command{
		Use:   "status HANDLE active|suspended",
		Short: "Set account status",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := domain.Status(args[1])
			if target != domain.StatusActive && target != domain.StatusSuspended {
				return fmt.Errorf("status must be active or suspended")
			}
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
			u, err := rt.store.UserByHandle(args[0])
			if err != nil {
				return err
			}
			if err := rt.admin.SetUserStatus(context.Background(), cliAdminActor(), u.ID, target); err != nil {
				return err
			}
			fmt.Printf("%s is now %s\n", u.Handle, target)
			return nil
		},
	}

	user.AddCommand(create, list, setRole, promote, passwd, status, adminKeyCmd(configPath))
	return user
}

// adminKeyCmd manages enrolled SSH public keys used by key authentication.
func adminKeyCmd(configPath *string) *cobra.Command {
	key := &cobra.Command{
		Use:   "key",
		Short: "Manage SSH public keys",
		RunE:  func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}

	add := &cobra.Command{
		Use:   "add HANDLE KEYFILE",
		Short: "Enroll a public key (authorized_keys line or .pub file)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			pub, _, _, _, err := gossh.ParseAuthorizedKey(raw)
			if err != nil {
				return fmt.Errorf("parse %s: %w", args[1], err)
			}
			fp := sshtransport.Fingerprint(pub)
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				u, err := rt.store.UserByHandle(args[0])
				if err != nil {
					return err
				}
				if err := rt.store.AddSSHKey(u.ID, fp, string(gossh.MarshalAuthorizedKey(pub))); err != nil {
					return err
				}
				_ = rt.store.RecordAudit(domain.AuditEntry{Actor: "cli", Action: "user.ssh_key_add",
					TargetKind: "user", TargetID: u.ID, Detail: fmt.Sprintf(`{"fingerprint":%q}`, fp)})
				fmt.Printf("enrolled %s for %s\n", fp, u.Handle)
				return nil
			})
		},
	}

	list := &cobra.Command{
		Use:   "list HANDLE",
		Short: "List an account's keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				u, err := rt.store.UserByHandle(args[0])
				if err != nil {
					return err
				}
				keys, err := rt.store.SSHKeys(u.ID)
				if err != nil {
					return err
				}
				tw := adminTabWriter()
				fmt.Fprintln(tw, "FINGERPRINT\tENROLLED\tKEY")
				for _, k := range keys {
					fmt.Fprintf(tw, "%s\t%s\t%s\n", k.Fingerprint, k.CreatedAt.Format("2006-01-02"), k.Key)
				}
				return tw.Flush()
			})
		},
	}

	remove := &cobra.Command{
		Use:   "remove HANDLE FINGERPRINT",
		Short: "Remove an enrolled key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return adminWithRuntime(*configPath, func(rt *runtime) error {
				u, err := rt.store.UserByHandle(args[0])
				if err != nil {
					return err
				}
				if err := rt.store.RemoveSSHKey(u.ID, args[1]); err != nil {
					return err
				}
				_ = rt.store.RecordAudit(domain.AuditEntry{Actor: "cli", Action: "user.ssh_key_remove",
					TargetKind: "user", TargetID: u.ID, Detail: fmt.Sprintf(`{"fingerprint":%q}`, args[1])})
				fmt.Printf("removed %s from %s\n", args[1], u.Handle)
				return nil
			})
		},
	}

	key.AddCommand(add, list, remove)
	return key
}

func randomPassword() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "changeme-please"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// adminResolvePassword picks the new password from --password or
// --password-file, or generates one. generated is true only when a fresh
// password was created. Reading from a file keeps secrets out of shell
// history and the process list.
func adminResolvePassword(flagValue, flagFile string) (pw string, generated bool, err error) {
	if flagValue != "" && flagFile != "" {
		return "", false, errors.New("use --password or --password-file, not both")
	}
	switch {
	case flagFile != "":
		b, err := os.ReadFile(flagFile)
		if err != nil {
			return "", false, fmt.Errorf("read password file: %w", err)
		}
		pw = strings.TrimSpace(string(b))
		if pw == "" {
			return "", false, errors.New("password file is empty")
		}
		return pw, false, nil
	case flagValue != "":
		return flagValue, false, nil
	default:
		return randomPassword(), true, nil
	}
}
