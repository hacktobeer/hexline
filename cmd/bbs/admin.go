package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/service"
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

	var handle, role, password, realName string
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
			generated := false
			if password == "" {
				password = randomPassword()
				generated = true
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
				AllowClosed: true, AllowReserved: true,
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
	create.Flags().StringVar(&password, "password", "", "password (generated when empty)")
	create.Flags().StringVar(&realName, "name", "", "real name (optional)")

	var roleFlag string
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
			u, err := rt.store.UserByHandle(args[0])
			if err != nil {
				return err
			}
			if err := rt.store.SetRole(u.ID, r); err != nil {
				return err
			}
			_ = rt.store.RecordAudit(domain.AuditEntry{Actor: "cli", Action: "user.role",
				TargetKind: "user", TargetID: u.ID, Detail: fmt.Sprintf(`{"role":%q}`, r)})
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
			u, err := rt.store.UserByHandle(args[0])
			if err != nil {
				return err
			}
			if err := rt.auth.Promote(context.Background(), nil, u.ID); err != nil {
				return err
			}
			fmt.Printf("%s is now active\n", u.Handle)
			return nil
		},
	}

	var newPassword string
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
			if newPassword == "" {
				newPassword = randomPassword()
			}
			if err := rt.auth.ResetPassword(context.Background(), args[0], newPassword); err != nil {
				return err
			}
			fmt.Printf("password for %s: %s\n", args[0], newPassword)
			return nil
		},
	}
	passwd.Flags().StringVar(&newPassword, "password", "", "new password (generated when empty)")

	var suspend bool
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
			u, err := rt.store.UserByHandle(args[0])
			if err != nil {
				return err
			}
			if err := rt.store.SetStatus(u.ID, target); err != nil {
				return err
			}
			_ = rt.store.RecordAudit(domain.AuditEntry{Actor: "cli", Action: "user.status",
				TargetKind: "user", TargetID: u.ID, Detail: fmt.Sprintf(`{"status":%q}`, target)})
			fmt.Printf("%s is now %s\n", u.Handle, target)
			return nil
		},
	}
	_ = suspend
	_ = roleFlag

	user.AddCommand(create, list, setRole, promote, passwd, status)
	return user
}

func randomPassword() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "changeme-please"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
