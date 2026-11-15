package service

import (
	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/store"
)

// Community implements oneliners, polls, bulletins, chat history and presence.
type Community struct {
	st     *store.Store
	cfg    *config.Config
	broker *hub.Broker
}

// NewCommunity wires the community service.
func NewCommunity(st *store.Store, cfg *config.Config, broker *hub.Broker) *Community {
	return &Community{st: st, cfg: cfg, broker: broker}
}
