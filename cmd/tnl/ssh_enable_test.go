package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
)

const retrySSHServer = "https://control.example.test"
const retrySSHTeam = "tm_0123456789abcdefghijkl"
const retrySSHIdentity = "ident_0123456789abcdefghijkl"

type sshSetupRetryAPI struct {
	urlID, createKey     string
	createRequest        []byte
	creates, enrollments int
	loseCreate           bool
	conflict             bool
}

func (f *sshSetupRetryAPI) CreatePublicURL(_ context.Context, request controlv1.CreatePublicURLRequest, key string) (controlv1.PublicURL, error) {
	f.creates++
	if f.conflict {
		return controlv1.PublicURL{}, controlclient.ErrNameUnavailable
	}
	encoded, _ := json.Marshal(request)
	if f.createKey != "" && (key != f.createKey || !bytes.Equal(f.createRequest, encoded)) {
		return controlv1.PublicURL{}, errors.New("URL retry replaced its key or request")
	}
	f.createKey, f.createRequest = key, encoded
	if f.loseCreate {
		f.loseCreate = false
		return controlv1.PublicURL{}, io.ErrUnexpectedEOF
	}
	if f.urlID == "" {
		f.urlID = "url_0123456789abcdefghijkl"
	}
	port := 2222
	return controlv1.PublicURL{Id: f.urlID, TeamId: request.TeamId, CanonicalHostname: request.CanonicalHostname, PublicPort: &port, ServiceProtocol: controlv1.Ssh, AccessMode: controlv1.Restricted, SshHostKey: request.SshHostKey}, nil
}

func (f *sshSetupRetryAPI) CreatePublisherEnrollment(_ context.Context, request controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error) {
	f.enrollments++
	id, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	if err != nil {
		return controlv1.PublisherEnrollment{}, err
	}
	return controlv1.PublisherEnrollment{Id: id, EnrollmentKey: id + ".one-use", TeamId: request.TeamId, Kind: "saved_url", PublicUrlId: request.PublicUrlId, ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func sshSetupRetryState(t *testing.T) (*clientstate.Database, *clientstate.Store, controlv1.CreatePublicURLRequest) {
	t.Helper()
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "user"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store, err := database.Server(t.Context(), retrySSHServer)
	if err != nil {
		t.Fatal(err)
	}
	return database, store, controlv1.CreatePublicURLRequest{TeamId: retrySSHTeam, CanonicalHostname: "workstation.example.test", DomainId: "dom_0123456789abcdefghijkl", PublicUrlScope: controlv1.Shared, Purpose: controlv1.App}
}

func loadSSHRetryJournal(t *testing.T, store *clientstate.Store, request controlv1.CreatePublicURLRequest, users []string) (*sshHostSetupJournal, *clientstate.SSHHostSetupState) {
	t.Helper()
	state, err := store.LockSSHHostSetup(t.Context(), request.TeamId, request.CanonicalHostname)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := openSSHHostSetup(t.Context(), state, request, "workstation", users, retrySSHServer, retrySSHIdentity)
	if err != nil {
		state.Close()
		t.Fatal(err)
	}
	return journal, state
}

func TestSSHEnableRetryPreservesURLKeyAndExplicitGrantKeys(t *testing.T) {
	database, store, request := sshSetupRetryState(t)
	api := &sshSetupRetryAPI{loseCreate: true}
	journal, state := loadSSHRetryJournal(t, store, request, []string{"deploy", "chase"})
	originalPrivate := bytes.Clone(journal.record.HostPrivateKey)
	originalURLKey := journal.record.URLKey
	originalGrantKeys := map[string]string{}
	for account, key := range journal.record.GrantKeys {
		originalGrantKeys[account] = key
	}
	grantCalls := map[string]int{}
	loseGrant := true
	grant := func(_ context.Context, _ string, account string) error {
		grantCalls[account]++
		if journal.record.GrantKeys[account] != originalGrantKeys[account] {
			return errors.New("grant key replaced")
		}
		if account == "deploy" && loseGrant {
			loseGrant = false
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	install := func(context.Context, sshHostInstallPayload, io.Writer) error { return nil }
	if _, err := completeSSHHostSetup(t.Context(), api, journal, install, io.Discard, grant); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	state.Close()
	journal, state = loadSSHRetryJournal(t, store, request, []string{"chase", "deploy"})
	if _, err := completeSSHHostSetup(t.Context(), api, journal, install, io.Discard, grant); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if !bytes.Equal(originalPrivate, journal.record.HostPrivateKey) || originalURLKey != journal.record.URLKey {
		t.Fatal("retry replaced the host identity")
	}
	assertSSHSecretsProtected(t, database.Root(), journal.record)
	state.Close()
	journal, state = loadSSHRetryJournal(t, store, request, []string{"deploy", "chase"})
	if _, err := completeSSHHostSetup(t.Context(), api, journal, install, io.Discard, grant); err != nil {
		t.Fatal(err)
	}
	if api.creates != 2 || api.enrollments != 1 || grantCalls["chase"] != 1 || grantCalls["deploy"] != 2 {
		t.Fatalf("unexpected repeated mutations: creates=%d enrollments=%d grants=%v", api.creates, api.enrollments, grantCalls)
	}
	data, found, err := state.Read(t.Context())
	if err != nil || !found {
		t.Fatal(err)
	}
	for _, secret := range []string{originalURLKey, originalGrantKeys["deploy"], base64.StdEncoding.EncodeToString(originalPrivate)} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("completed setup retained a credential")
		}
	}
	state.Close()
	state, err = store.LockSSHHostSetup(t.Context(), request.TeamId, request.CanonicalHostname)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if _, err := openSSHHostSetup(t.Context(), state, request, "workstation", []string{"chase", "deploy"}, retrySSHServer, retrySSHIdentity); err == nil || !strings.Contains(err.Error(), "already completed") {
		t.Fatalf("completed setup started again: %v", err)
	}
}

func assertSSHSecretsProtected(t *testing.T, root string, record *sshHostSetup) {
	t.Helper()
	secrets := []string{record.URLKey, record.EnrollmentKey, base64.StdEncoding.EncodeToString(record.HostPrivateKey)}
	for _, key := range record.GrantKeys {
		secrets = append(secrets, key)
	}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, secret := range secrets {
			if secret != "" && bytes.Contains(data, []byte(secret)) {
				return errors.New("plaintext SSH credential found in client state")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v %#v %v %#v", record, record, *record, *record)
	var output bytes.Buffer
	writeCommandError(&output, invalidSSHSetupState())
	for _, secret := range secrets {
		if secret != "" && (strings.Contains(formatted, secret) || bytes.Contains(output.Bytes(), []byte(secret))) {
			t.Fatal("SSH recovery credential leaked into diagnostics")
		}
	}
}

func TestSSHEnablePendingAccountsCannotBeChangedOrTakenOver(t *testing.T) {
	_, store, request := sshSetupRetryState(t)
	_, state := loadSSHRetryJournal(t, store, request, []string{"deploy"})
	defer state.Close()
	for _, users := range [][]string{{"deploy", "chase"}, {"chase"}} {
		if _, err := openSSHHostSetup(t.Context(), state, request, "workstation", users, retrySSHServer, retrySSHIdentity); err == nil {
			t.Fatal("pending allowlist silently changed")
		}
	}
	if _, err := openSSHHostSetup(t.Context(), state, request, "workstation", []string{"deploy"}, retrySSHServer, "ident_abcdefghijkl0123456789"); err == nil {
		t.Fatal("pending identity silently changed")
	}
	journal, err := openSSHHostSetup(t.Context(), state, request, "workstation", []string{"deploy"}, retrySSHServer, retrySSHIdentity)
	if err != nil {
		t.Fatal(err)
	}
	api := &sshSetupRetryAPI{conflict: true}
	_, err = completeSSHHostSetup(t.Context(), api, journal, func(context.Context, sshHostInstallPayload, io.Writer) error {
		t.Fatal("conflicting host reached installer")
		return nil
	}, io.Discard, func(context.Context, string, string) error { return nil })
	if !errors.Is(err, controlclient.ErrNameUnavailable) || !strings.Contains(err.Error(), "another saved public URL") {
		t.Fatalf("host conflict did not explain non-takeover: %v", err)
	}
}

func TestSSHEnableLostInstallResponseReusesActualRootIdentity(t *testing.T) {
	current, err := user.Current()
	if err != nil || !validSSHAccount(current.Username) || managedssh.ValidateUsers([]string{current.Username}) != nil {
		t.Skip("a nonroot current account is required for the registry boundary")
	}
	database, store, request := sshSetupRetryState(t)
	registry, authority, control, _ := backgroundFixture(t)
	authority.identity.TeamId = retrySSHTeam
	api := &sshSetupRetryAPI{urlID: *authority.identity.PublicUrlId}
	journal, state := loadSSHRetryJournal(t, store, request, []string{current.Username})
	installCalls := 0
	var firstPayload sshHostInstallPayload
	install := func(ctx context.Context, payload sshHostInstallPayload, _ io.Writer) error {
		installCalls++
		if installCalls == 1 {
			firstPayload = payload
		} else if !reflect.DeepEqual(payload, firstPayload) {
			t.Fatal("lost-response retry changed the install payload")
		}
		signer, err := managedssh.ParseHostKey(payload.HostPrivateKey)
		if err != nil {
			return err
		}
		pin := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
		control.publicURL = controlv1.PublicURL{Id: payload.PublicURLID, TeamId: payload.TeamID, CanonicalHostname: payload.Hostname, PublicPort: &payload.PublicPort, ServiceProtocol: controlv1.Ssh, AccessMode: controlv1.Restricted, LifecycleState: controlv1.Enabled, Purpose: controlv1.App, SshHostKey: &pin}
		if err := installSSHHostJob(ctx, registry, payload, func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
			return control, authority, nil
		}); err != nil {
			return err
		}
		if installCalls == 1 {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	grant := func(context.Context, string, string) error { return nil }
	if _, err := completeSSHHostSetup(t.Context(), api, journal, install, io.Discard, grant); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	assertSSHSecretsProtected(t, database.Root(), journal.record)
	state.Close()
	journal, state = loadSSHRetryJournal(t, store, request, []string{current.Username})
	defer state.Close()
	if _, err := completeSSHHostSetup(t.Context(), api, journal, install, io.Discard, grant); err != nil {
		t.Fatal(err)
	}
	jobs, err := registry.List(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].PublisherID != authority.identity.ClientId || jobs[0].Revision != 1 || authority.redemptions != 1 || api.enrollments != 1 || api.creates != 1 {
		t.Fatalf("retry created or replaced a publisher identity: err=%v jobs=%d redemptions=%d enrollments=%d", err, len(jobs), authority.redemptions, api.enrollments)
	}
}

func TestSSHEnableOlderPendingSetupRecoversPortWithoutReplacingCredentials(t *testing.T) {
	_, store, request := sshSetupRetryState(t)
	api := &sshSetupRetryAPI{}
	journal, state := loadSSHRetryJournal(t, store, request, []string{"deploy"})
	grant := func(context.Context, string, string) error { return nil }
	original, err := prepareSSHHost(t.Context(), api, request, "workstation", journal.record.Users, retrySSHServer, grant, journal)
	if err != nil {
		t.Fatal(err)
	}
	journal.record.PublicPort = 0
	if err := journal.save(t.Context()); err != nil {
		t.Fatal(err)
	}
	state.Close()
	journal, state = loadSSHRetryJournal(t, store, request, []string{"deploy"})
	defer state.Close()
	recovered, err := prepareSSHHost(t.Context(), api, request, "workstation", journal.record.Users, retrySSHServer, grant, journal)
	if err != nil || !reflect.DeepEqual(original, recovered) || api.creates != 2 || api.enrollments != 1 {
		t.Fatalf("older setup retry replaced its scope or credentials: %v", err)
	}
}

func TestSSHEnableExpiredEnrollmentRefreshKeepsOriginalHostKey(t *testing.T) {
	_, store, request := sshSetupRetryState(t)
	api := &sshSetupRetryAPI{}
	journal, state := loadSSHRetryJournal(t, store, request, []string{"deploy"})
	defer state.Close()
	grant := func(context.Context, string, string) error { return nil }
	if _, err := prepareSSHHost(t.Context(), api, request, "workstation", journal.record.Users, retrySSHServer, grant, journal); err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(journal.record.HostPrivateKey)
	oldEnrollment := journal.record.EnrollmentKey
	journal.record.InstallAttempted = true
	journal.record.EnrollmentExpiresAt = time.Now().Add(-time.Minute)
	if err := journal.save(t.Context()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err := completeSSHHostSetup(t.Context(), api, journal, func(_ context.Context, payload sshHostInstallPayload, _ io.Writer) error {
		calls++
		if !bytes.Equal(payload.HostPrivateKey, original) {
			t.Fatal("enrollment refresh replaced the host key")
		}
		if calls == 1 {
			if payload.EnrollmentKey != oldEnrollment {
				t.Fatal("old enrollment was not tried first")
			}
			return errSSHEnrollmentRefresh
		}
		if payload.EnrollmentKey == oldEnrollment {
			t.Fatal("expired enrollment was not replaced")
		}
		return nil
	}, io.Discard, grant)
	if err != nil || calls != 2 || api.enrollments != 2 || api.creates != 1 {
		t.Fatalf("bounded enrollment refresh failed: %v calls=%d enrollments=%d", err, calls, api.enrollments)
	}
}

func TestSSHEnableCheckpointFailureDoesNotDeliverEnrollmentToRoot(t *testing.T) {
	_, store, request := sshSetupRetryState(t)
	journal, state := loadSSHRetryJournal(t, store, request, []string{"deploy"})
	api := &sshSetupRetryAPI{}
	write := journal.write
	writeErr := errors.New("private checkpoint could not be written")
	journal.write = func(ctx context.Context, data []byte) error {
		if journal.record.InstallAttempted {
			return writeErr
		}
		return write(ctx, data)
	}
	grant := func(context.Context, string, string) error { return nil }
	if _, err := completeSSHHostSetup(t.Context(), api, journal, func(context.Context, sshHostInstallPayload, io.Writer) error {
		t.Fatal("enrollment delivered to root without a durable checkpoint")
		return nil
	}, io.Discard, grant); !errors.Is(err, writeErr) {
		t.Fatal(err)
	}
	original := sshHostSetupPayload(journal.record)
	state.Close()
	journal, state = loadSSHRetryJournal(t, store, request, []string{"deploy"})
	defer state.Close()
	if journal.record.InstallAttempted {
		t.Fatal("failed checkpoint was treated as a completed write")
	}
	if _, err := completeSSHHostSetup(t.Context(), api, journal, func(_ context.Context, payload sshHostInstallPayload, _ io.Writer) error {
		if !reflect.DeepEqual(payload, original) {
			t.Fatal("checkpoint retry replaced pending credentials")
		}
		return nil
	}, io.Discard, grant); err != nil {
		t.Fatal(err)
	}
	if api.creates != 1 || api.enrollments != 1 {
		t.Fatal("checkpoint retry repeated successful control mutations")
	}
}
