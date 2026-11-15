package service

import (
	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/store"
)

// Admin implements privileged operations and the audit trail.
type Admin struct {
	st     *store.Store
	cfg    *config.Config
	broker *hub.Broker
}

// NewAdmin wires the admin service.
func NewAdmin(st *store.Store, cfg *config.Config, broker *hub.Broker) *Admin {
	return &Admin{st: st, cfg: cfg, broker: broker}
}
