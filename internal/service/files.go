package service

import (
	"context"
	"io"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/store"
)

// Files implements file areas, uploads, downloads and ratings.
type Files struct {
	st  *store.Store
	cfg *config.Config
}

// NewFiles wires the file service.
func NewFiles(st *store.Store, cfg *config.Config) *Files {
	return &Files{st: st, cfg: cfg}
}

// OpenDownload resolves "AREA/FILE" for the non-interactive `bbs get` pipe.
func (f *Files) OpenDownload(ctx context.Context, user *domain.User, areaTag, filename string) (io.ReadCloser, *domain.File, error) {
	return nil, nil, domain.ErrUnavailable
}
