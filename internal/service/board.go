package service

import (
	"context"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/store"
)

// Boards implements message areas, threads, posts, read tracking and search.
type Boards struct {
	st  *store.Store
	cfg *config.Config
}

// NewBoards wires the board service.
func NewBoards(st *store.Store, cfg *config.Config) *Boards {
	return &Boards{st: st, cfg: cfg}
}

// UnreadTotal counts unread posts across every area the user can read.
func (b *Boards) UnreadTotal(ctx context.Context, userID string) (int, error) {
	return 0, nil
}
