package service

import (
	"context"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/store"
)

// Mail implements private mail.
type Mail struct {
	st  *store.Store
	cfg *config.Config
}

// NewMail wires the mail service.
func NewMail(st *store.Store, cfg *config.Config) *Mail {
	return &Mail{st: st, cfg: cfg}
}

// UnreadCount counts unread mail for a user.
func (m *Mail) UnreadCount(ctx context.Context, userID string) (int, error) {
	return 0, nil
}
