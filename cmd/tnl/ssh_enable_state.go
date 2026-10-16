package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
)

type sshHostSetup struct {
	Version                     int `json:"version"`
	Server, Name, IdentityID    string
	Request                     controlv1.CreatePublicURLRequest
	Users                       []string
	HostPrivateKey              []byte
	URLKey, PublicURLID         string
	PublicPort                  int
	GrantKeys                   map[string]string
	Granted                     map[string]bool
	EnrollmentKey               string
	EnrollmentExpiresAt         time.Time
	InstallAttempted, Completed bool
}

// String excludes the recovery document from incidental error formatting.
func (sshHostSetup) String() string     { return "private SSH host setup" }
func (s sshHostSetup) GoString() string { return s.String() }

type sshHostSetupJournal struct {
	record *sshHostSetup
	write  func(context.Context, []byte) error
}

func (j *sshHostSetupJournal) save(ctx context.Context) error {
	if j.write == nil {
		return nil
	}
	data, err := json.Marshal(j.record)
	if err != nil {
		return failure.Wrap("encode private SSH setup", failure.ClientStateUnavailable, err)
	}
	return j.write(ctx, data)
}

func newSSHHostSetup(request controlv1.CreatePublicURLRequest, name string, users []string, server, identity string) (*sshHostSetup, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return nil, err
	}
	users = slices.Clone(users)
	slices.Sort(users)
	record := &sshHostSetup{Version: 1, Server: server, Name: name, IdentityID: identity, Request: request, Users: users, HostPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), URLKey: key, GrantKeys: map[string]string{}, Granted: map[string]bool{}}
	for _, account := range users {
		key, err := randomIdempotencyKey()
		if err != nil {
			return nil, err
		}
		record.GrantKeys[account] = key
	}
	return record, nil
}

func openSSHHostSetup(ctx context.Context, state *clientstate.SSHHostSetupState, request controlv1.CreatePublicURLRequest, name string, users []string, server, identity string) (*sshHostSetupJournal, error) {
	data, found, err := state.Read(ctx)
	if err != nil {
		return nil, err
	}
	journal := &sshHostSetupJournal{write: state.Save}
	if !found {
		journal.record, err = newSSHHostSetup(request, name, users, server, identity)
		if err != nil {
			return nil, err
		}
		return journal, journal.save(ctx)
	}
	var record sshHostSetup
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, invalidSSHSetupState()
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || record.Version != 1 {
		return nil, invalidSSHSetupState()
	}
	users = slices.Clone(users)
	slices.Sort(users)
	expected, _ := json.Marshal(request)
	stored, _ := json.Marshal(record.Request)
	if record.Server != server || record.Name != name || record.IdentityID != identity || !bytes.Equal(stored, expected) || !slices.Equal(record.Users, users) {
		return nil, &sshCommandError{message: "SSH setup already exists with a different account set or ownership scope", action: "retry with the original account set and identity; enable does not reconfigure or take over another host", reason: failure.ServerConflict}
	}
	if record.Completed {
		return nil, &sshCommandError{message: "SSH host setup has already completed", action: "inspect it with sudo tnl service status " + name + "; use the service commands to start or stop it", reason: failure.ServerConflict}
	}
	if !opaqueid.Valid(record.URLKey, opaqueid.IdempotencyPrefix) || len(record.HostPrivateKey) > 8192 {
		return nil, invalidSSHSetupState()
	}
	signer, err := managedssh.ParseHostKey(record.HostPrivateKey)
	if err != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, invalidSSHSetupState()
	}
	if record.PublicURLID == "" && record.PublicPort != 0 || record.PublicURLID != "" && (!opaqueid.Valid(record.PublicURLID, opaqueid.PublicURLPrefix) || record.PublicPort != 0 && !validSSHHostPublicPort(record.PublicPort)) {
		return nil, invalidSSHSetupState()
	}
	for _, account := range record.Users {
		if !opaqueid.Valid(record.GrantKeys[account], opaqueid.IdempotencyPrefix) {
			return nil, invalidSSHSetupState()
		}
	}
	if record.Granted == nil {
		return nil, invalidSSHSetupState()
	}
	journal.record = &record
	return journal, nil
}

func invalidSSHSetupState() error {
	return failure.Wrap("read private SSH setup", failure.ClientStateUnavailable, errors.New("private SSH setup is invalid; keep its original key and state for recovery"))
}

func completeSSHHostSetup(ctx context.Context, api sshHostSetupAPI, journal *sshHostSetupJournal, install func(context.Context, sshHostInstallPayload, io.Writer) error, diagnostics io.Writer, grant func(context.Context, string, string) error) (sshHostInstallPayload, error) {
	record := journal.record
	payload, err := prepareSSHHost(ctx, api, record.Request, record.Name, record.Users, record.Server, grant, journal)
	if err != nil {
		return sshHostInstallPayload{}, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		// checkpoint before giving a one-use credential to root. an uncertain
		// result must retry that same credential before considering replacement.
		record.InstallAttempted = true
		if err := journal.save(ctx); err != nil {
			return sshHostInstallPayload{}, err
		}
		err = install(ctx, payload, diagnostics)
		if !errors.Is(err, errSSHEnrollmentRefresh) || attempt == 1 {
			break
		}
		if err := issueSSHHostEnrollment(ctx, api, journal); err != nil {
			return sshHostInstallPayload{}, err
		}
		payload = sshHostSetupPayload(record)
	}
	if err != nil {
		return sshHostInstallPayload{}, err
	}
	// retain only metadata proving this local setup completed. neither the host
	// private key nor enrollment and idempotency credentials remain user-side.
	record.Completed = true
	record.HostPrivateKey, record.GrantKeys, record.Granted = nil, nil, nil
	record.URLKey, record.EnrollmentKey = "", ""
	record.EnrollmentExpiresAt = time.Time{}
	if err := journal.save(ctx); err != nil {
		return sshHostInstallPayload{}, err
	}
	return payload, nil
}

func sshHostSetupPayload(record *sshHostSetup) sshHostInstallPayload {
	return sshHostInstallPayload{Version: 1, Name: record.Name, Server: record.Server, PublicURLID: record.PublicURLID, TeamID: record.Request.TeamId, Hostname: record.Request.CanonicalHostname, PublicPort: record.PublicPort, Users: slices.Clone(record.Users), EnrollmentKey: record.EnrollmentKey, EnrollmentExpiresAt: record.EnrollmentExpiresAt, HostPrivateKey: bytes.Clone(record.HostPrivateKey)}
}

func issueSSHHostEnrollment(ctx context.Context, api sshHostSetupAPI, journal *sshHostSetupJournal) error {
	record := journal.record
	enrollment, err := api.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: record.Request.TeamId, PublicUrlId: &record.PublicURLID, Name: record.Name, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled})
	if err != nil {
		return err
	}
	if !opaqueid.Valid(enrollment.Id, opaqueid.PublisherEnrollmentPrefix) || !strings.HasPrefix(enrollment.EnrollmentKey, enrollment.Id+".") || enrollment.TeamId != record.Request.TeamId || enrollment.Kind != "saved_url" || enrollment.PublicUrlId == nil || *enrollment.PublicUrlId != record.PublicURLID || enrollment.DomainId != nil || enrollment.Namespace != nil || !enrollment.ExpiresAt.After(time.Now()) {
		return failure.Wrap("read SSH publisher enrollment", failure.ServerResponseInvalid, errors.New("control returned a different enrollment scope"))
	}
	record.EnrollmentKey, record.EnrollmentExpiresAt, record.InstallAttempted = enrollment.EnrollmentKey, enrollment.ExpiresAt.UTC(), false
	return journal.save(ctx)
}
