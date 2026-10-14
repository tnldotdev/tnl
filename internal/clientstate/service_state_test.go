package clientstate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceStateUsesFileKeyAcrossRestart(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "service")
	first, err := OpenService(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := first.Server(ctx, "https://control.example.com")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := profile.secrets.Seal(ctx, "certificate", []byte("private material"))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenService(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	profile, err = second.Server(ctx, "https://control.example.com")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := profile.secrets.Open(ctx, "certificate", sealed)
	if err != nil || string(opened) != "private material" {
		t.Fatalf("service key did not survive restart: %v", err)
	}
	second.Close()
	if err := os.Remove(filepath.Join(root, "wrapping-key-v1")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenService(ctx, root); err == nil {
		t.Fatal("recreated missing service key")
	}
}
