package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdminResolvePassword(t *testing.T) {
	gen, generated, err := adminResolvePassword("", "")
	if err != nil || !generated || len(gen) == 0 {
		t.Fatalf("generated = %q, %v, %v", gen, generated, err)
	}

	explicit, generated, err := adminResolvePassword("secret-123", "")
	if err != nil || generated || explicit != "secret-123" {
		t.Fatalf("explicit = %q, %v, %v", explicit, generated, err)
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "pw")
	if err := os.WriteFile(file, []byte("  file-secret-456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, generated, err := adminResolvePassword("", file)
	if err != nil || generated || fromFile != "file-secret-456" {
		t.Fatalf("from file = %q, %v, %v", fromFile, generated, err)
	}

	if _, _, err := adminResolvePassword("both", file); err == nil {
		t.Fatal("both flags accepted together")
	}
	if _, _, err := adminResolvePassword("", filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "empty"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adminResolvePassword("", filepath.Join(dir, "empty")); err == nil {
		t.Fatal("empty file accepted")
	}
}
