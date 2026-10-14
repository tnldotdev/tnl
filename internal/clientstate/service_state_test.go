package clientstate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceStateOpensPrivateDataWithoutLoginKeychain(t *testing.T) {
	root := filepath.Join(t.TempDir(), "service")
	first, err := OpenService(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	server, err := first.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := server.secrets.Seal(t.Context(), "publisher:one", []byte("private-key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(root, "wrapping-key-v1"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("service wrapping key permissions = %v, %v", info, err)
	}
	second, err := OpenService(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	server, err = second.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := server.secrets.Open(t.Context(), "publisher:one", sealed)
	if err != nil || string(opened) != "private-key" {
		t.Fatalf("service key after restart = %q, %v", opened, err)
	}
	if _, err := server.secrets.Open(t.Context(), "publisher:another", sealed); err == nil {
		t.Fatal("a different publisher opened the service secret")
	}
}

func TestServicePublisherJobSurvivesRestartWithoutLeakingKey(t *testing.T) {
	const id = "url_0123456789abcdefghijkl"
	root := filepath.Join(t.TempDir(), "service")
	first, err := OpenService(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("private-publisher-signing-key")
	job := PublisherJob{PublicURLID: id, Server: "https://control.example.test", Target: "127.0.0.1:22", Protocol: "ssh", Identity: key}
	if err := first.SavePublisherJob(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := first.db.QueryRowContext(t.Context(), "SELECT stored_identity FROM publisher_jobs WHERE public_url_id = ?", id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, key) {
		t.Fatal("publisher signing key stored in plaintext")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenService(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	jobs, err := second.PublisherJobs(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].PublicURLID != id || jobs[0].Target != job.Target || !bytes.Equal(jobs[0].Identity, key) {
		t.Fatalf("saved publisher job did not survive restart: %v", err)
	}
	if err := second.DeletePublisherJob(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	jobs, err = second.PublisherJobs(t.Context())
	if err != nil || len(jobs) != 0 {
		t.Fatalf("removed publisher job remained: %v", err)
	}
}
