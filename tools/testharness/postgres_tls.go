package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

func preparePostgresTLS(ctx context.Context, database testcontainers.Container) (certificate, key string, cleanup func(), err error) {
	directory, err := os.MkdirTemp("", "tnl-postgres-tls-")
	if err != nil {
		return "", "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(directory) }
	setup, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	certificate, key = filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	request := exec.CommandContext(setup, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", key, "-out", certificate, "-days", "1", "-subj", "/CN=route.example",
		"-addext", "subjectAltName=DNS:route.example,DNS:db.internal")
	if output, err := request.CombinedOutput(); err != nil {
		return "", "", cleanup, fmt.Errorf("create disposable PostgreSQL certificate: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	for _, file := range []struct {
		path string
		mode int64
	}{{certificate, 0644}, {key, 0600}} {
		if err := database.CopyFileToContainer(setup, file.path, "/var/lib/postgresql/data/"+filepath.Base(file.path), file.mode); err != nil {
			return "", "", cleanup, fmt.Errorf("install disposable PostgreSQL certificate: %w", err)
		}
	}
	for _, operation := range []struct {
		user    string
		command []string
	}{
		{"root", []string{"chown", "postgres:postgres", "/var/lib/postgresql/data/server.crt", "/var/lib/postgresql/data/server.key"}},
		{"root", []string{"chmod", "0600", "/var/lib/postgresql/data/server.key"}},
		{"postgres", []string{"psql", "--username", "postgres", "--dbname", "postgres", "-c", "ALTER SYSTEM SET ssl = on"}},
		{"postgres", []string{"pg_ctl", "-D", "/var/lib/postgresql/data", "reload"}},
	} {
		if _, err := postgresExec(setup, database, operation.user, operation.command...); err != nil {
			return "", "", cleanup, err
		}
	}
	for {
		state, err := postgresExec(setup, database, "postgres", "psql", "--username", "postgres", "--dbname", "postgres", "-tAc", "SHOW ssl")
		if err != nil {
			return "", "", cleanup, err
		}
		if strings.TrimSpace(state) == "on" {
			return certificate, key, cleanup, nil
		}
		select {
		case <-setup.Done():
			return "", "", cleanup, fmt.Errorf("wait for disposable PostgreSQL TLS: %w", setup.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func postgresExec(ctx context.Context, database testcontainers.Container, user string, command ...string) (string, error) {
	code, output, err := database.Exec(ctx, command, tcexec.WithUser(user))
	var stdout, stderr bytes.Buffer
	if output != nil {
		_, readErr := stdcopy.StdCopy(&stdout, &stderr, io.LimitReader(output, 4096))
		err = errors.Join(err, readErr)
	}
	if err != nil {
		return "", fmt.Errorf("configure disposable PostgreSQL TLS (%s): %w (%s)", command[0], err, strings.TrimSpace(stderr.String()))
	}
	if code != 0 {
		return "", fmt.Errorf("configure disposable PostgreSQL TLS (%s): exit %d (%s)", command[0], code, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
