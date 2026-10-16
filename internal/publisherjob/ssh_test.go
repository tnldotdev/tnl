package publisherjob

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
)

func sshFixture(t *testing.T) (Job, authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey) {
	t.Helper()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if current.Uid == "0" || current.Username == "root" {
		t.Skip("managed SSH requires an existing named non-root user")
	}
	job, identity, private := fixture(t, "shell")
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	job.Protocol, job.Target = "ssh", ""
	job.SSHUsers = []string{current.Username}
	job.SSHHostKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return job, identity, private
}

func TestManagedSSHValidation(t *testing.T) {
	job, _, _ := sshFixture(t)
	if err := validateJob(&job); err != nil {
		t.Fatalf("valid managed SSH job: %v", err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := x509.MarshalPKCS8PrivateKey(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Job){
		"forwarding target": func(j *Job) { j.Target = "localhost:22" },
		"target TLS":        func(j *Job) { j.TargetTLS = true },
		"target TLS name":   func(j *Job) { j.TargetTLSName = "localhost" },
		"target CA":         func(j *Job) { j.TargetCAPEM = []byte("certificate") },
		"missing users":     func(j *Job) { j.SSHUsers = nil },
		"duplicate users":   func(j *Job) { j.SSHUsers = []string{job.SSHUsers[0], job.SSHUsers[0]} },
		"root user":         func(j *Job) { j.SSHUsers = []string{"root"} },
		"numeric user":      func(j *Job) { j.SSHUsers = []string{"0"} },
		"missing host key":  func(j *Job) { j.SSHHostKey = nil },
		"invalid host key":  func(j *Job) { j.SSHHostKey = []byte("host-private-secret") },
		"oversize host key": func(j *Job) { j.SSHHostKey = bytes.Repeat([]byte("x"), (16<<10)+1) },
		"non-ed25519 host key": func(j *Job) {
			j.SSHHostKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wrongDER})
		},
		"invalid server CA": func(j *Job) { j.ServerCAPEM = []byte("certificate") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := job
			mutate(&changed)
			if err := validateJob(&changed); !errors.Is(err, ErrScope) {
				t.Fatalf("invalid managed SSH settings accepted: %v", err)
			} else if strings.Contains(err.Error(), "host-private-secret") {
				t.Fatal("host key entered validation error")
			}
		})
	}
}

func TestMissingSSHAccountDoesNotPoisonRegistry(t *testing.T) {
	r := testRegistry(t)
	job, identity, private := sshFixture(t)
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	// model a locally deleted account without changing the developer's OS.
	job.SSHUsers = []string{"tnl-missing-account"}
	if err := r.update(t.Context(), func(jobs *[]Job) error { (*jobs)[0].SSHUsers = job.SSHUsers; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := r.List(t.Context()); err != nil {
		t.Fatalf("deleted account made registry unreadable: %v", err)
	}
	if err := r.Stop(t.Context(), job.ID); err != nil {
		t.Fatalf("cannot stop deleted account job: %v", err)
	}
	if err := r.Install(t.Context(), job, identity, private); !errors.Is(err, ErrScope) {
		t.Fatalf("installation accepted missing account: %v", err)
	}
}

func TestNonSSHJobsRejectSSHSettings(t *testing.T) {
	for _, protocol := range []string{"http", "postgres", "mysql", "redis"} {
		for _, field := range []string{"users", "host key"} {
			t.Run(protocol+"/"+field, func(t *testing.T) {
				job, _, _ := fixture(t, "one")
				if protocol != "http" {
					job.Protocol = controlv1.PublicURLServiceProtocol(protocol)
					job.Target = "localhost:6379"
				}
				if field == "users" {
					job.SSHUsers = []string{"someone"}
				} else {
					job.SSHHostKey = []byte("host-private-secret")
				}
				if err := validateJob(&job); !errors.Is(err, ErrScope) {
					t.Fatalf("SSH-only settings accepted: %v", err)
				}
			})
		}
	}
}

func TestManagedSSHEncryptedRestartAndIdentity(t *testing.T) {
	options := testOptions(t)
	r, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	job, identity, private := sshFixture(t)
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	// include both raw PEM and JSON's base64 encoding in the plaintext check.
	encoded := []byte(base64.StdEncoding.EncodeToString(job.SSHHostKey))
	checkPrivate := func() {
		t.Helper()
		for _, suffix := range []string{"", "-wal", "-journal"} {
			value, err := os.ReadFile(clientstate.DatabasePath(options.Root) + suffix)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(value, job.SSHHostKey) || bytes.Contains(value, encoded) {
				t.Fatal("SSH host private key persisted in plaintext")
			}
		}
	}
	checkPrivate()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 {
		t.Fatalf("restore SSH jobs: %v", err)
	}
	if !bytes.Equal(jobs[0].SSHHostKey, job.SSHHostKey) || !slices.Equal(jobs[0].SSHUsers, job.SSHUsers) || jobs[0].Target != "" {
		t.Fatal("managed SSH settings changed across restart")
	}
	loaded, signingKey, _, err := r.signingIdentity(t.Context(), jobs[0])
	if err != nil || loaded.KeyId != identity.KeyId || !bytes.Equal(signingKey, private) {
		t.Fatalf("existing enrolled identity changed: %v", err)
	}
	checkPrivate()
	// malformed encrypted snapshots must fail closed on read too.
	jobs[0].SSHHostKey = nil
	value, err := json.Marshal(jobs)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.database.SaveSystemState(t.Context(), registryName, value); err != nil {
		t.Fatal(err)
	}
	if _, err := r.List(t.Context()); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("unsafe SSH snapshot accepted: %v", err)
	}
}

func TestJobFormattingDoesNotExposeSSHHostKey(t *testing.T) {
	job := Job{SSHHostKey: []byte("host-private-secret")}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		output := fmt.Sprintf(format, job)
		if strings.Contains(output, "host-private-secret") || strings.Contains(output, "104 111 115 116") {
			t.Fatalf("host key leaked through %s", format)
		}
	}
}

func TestManagedSSHRuntimeHook(t *testing.T) {
	r := testRegistry(t)
	job, identity, private := sshFixture(t)
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	control, authority := jobBoundary(job, identity, private)
	signer, err := managedssh.ParseHostKey(job.SSHHostKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	control.publicURL.SshHostKey, control.publicURL.AccessMode = &pin, controlv1.Restricted
	engine := Engine{Registry: r, Clients: func(Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
		return control, authority, nil
	}}
	published := false
	engine.Publish = func(_ context.Context, cfg publisher.Config) error {
		published = true
		if cfg.Target != "" || cfg.ServiceProtocol != "ssh" || cfg.SSH == nil || !slices.Equal(cfg.SSH.Users, job.SSHUsers) || !bytes.Equal(cfg.SSH.HostKey.PublicKey().Marshal(), signer.PublicKey().Marshal()) {
			t.Fatal("managed SSH became target forwarding")
		}
		return nil
	}
	if _, err := engine.attempt(t.Context(), job, 1); err != nil || !published {
		t.Fatalf("managed SSH runtime was not invoked: %v", err)
	}
	published = false
	control.publicURL.SshHostKey = nil
	if _, err := engine.attempt(t.Context(), job, 1); !errors.Is(err, ErrScope) || published {
		t.Fatal("missing registered host key reached publication")
	}
	control.publicURL.Target = "localhost:22"
	if _, err := publicationConfig(job, control.publicURL); !errors.Is(err, ErrScope) {
		t.Fatal("saved SSH forwarding target accepted")
	}
}
