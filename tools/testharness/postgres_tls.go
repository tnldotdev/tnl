package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

func preparePostgresTLS(ctx context.Context, database testcontainers.Container) (certificate, key, rootCA string, cleanup func(), err error) {
	directory, err := os.MkdirTemp("", "tnl-postgres-tls-")
	if err != nil {
		return "", "", "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(directory) }
	setup, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	certificate, key, rootCA, err = createPostgresTestCertificates(directory)
	if err != nil {
		return "", "", "", cleanup, fmt.Errorf("create disposable PostgreSQL certificates: %w", err)
	}
	for _, file := range []struct {
		path string
		mode int64
	}{{certificate, 0644}, {key, 0600}} {
		if err := database.CopyFileToContainer(setup, file.path, "/var/lib/postgresql/data/"+filepath.Base(file.path), file.mode); err != nil {
			return "", "", "", cleanup, fmt.Errorf("install disposable PostgreSQL certificate: %w", err)
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
			return "", "", "", cleanup, err
		}
	}
	for {
		state, err := postgresExec(setup, database, "postgres", "psql", "--username", "postgres", "--dbname", "postgres", "-tAc", "SHOW ssl")
		if err != nil {
			return "", "", "", cleanup, err
		}
		if strings.TrimSpace(state) == "on" {
			return certificate, key, rootCA, cleanup, nil
		}
		select {
		case <-setup.Done():
			return "", "", "", cleanup, fmt.Errorf("wait for disposable PostgreSQL TLS: %w", setup.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func createPostgresTestCertificates(directory string) (certificate, key, rootCA string, err error) {
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tnl disposable PostgreSQL CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		return "", "", "", err
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		return "", "", "", err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	server := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "route.example"},
		DNSNames:  []string{"route.example", "db.internal"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, root, &serverKey.PublicKey, rootKey)
	if err != nil {
		return "", "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return "", "", "", err
	}
	certificate = filepath.Join(directory, "server.crt")
	key = filepath.Join(directory, "server.key")
	rootCA = filepath.Join(directory, "root-ca.crt")
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0644},
		{key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600},
		{rootCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644},
	} {
		if err := os.WriteFile(file.path, file.data, file.mode); err != nil {
			return "", "", "", err
		}
	}
	return certificate, key, rootCA, nil
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
