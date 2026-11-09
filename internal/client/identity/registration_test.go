package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type registrationCall struct {
	key  string
	body controlv1.RegisterApplicationRequest
}
type registrationControl struct {
	calls       []registrationCall
	lost        bool
	alter       bool
	beforeReply func()
}

func (*registrationControl) ControlURL() string { return "https://control.example.test" }
func (c *registrationControl) RegisterApplication(_ context.Context, key string, request controlv1.RegisterApplicationRequest) (controlv1.RegisteredApplication, error) {
	c.calls = append(c.calls, registrationCall{key, request})
	result := controlv1.RegisteredApplication{ClientId: "pub_" + strings.Repeat("A", 22), KeyId: "pkey_" + strings.Repeat("B", 22), Name: request.Name, TeamId: request.TeamId, Ownership: controlv1.RegisteredApplicationOwnership(request.Ownership), Grants: make([]controlv1.PublisherGrant, 0, len(request.Grants))}
	for index, input := range request.Grants {
		grant := controlv1.PublisherGrant{Id: "pgrant_" + strings.Repeat(string(rune('C'+index)), 22), Operation: input.Operation, CreatedAt: time.Now(), ExpiresAt: input.ExpiresAt, PublicUrlId: input.PublicUrlId, ServiceId: input.ServiceId, DomainId: input.DomainId}
		switch {
		case input.PublicUrlId != nil:
			grant.Kind = "saved_public_url"
		case input.ServiceId != nil:
			grant.Kind = "service"
		default:
			grant.Kind = "namespace"
			namespace := "member.example.test"
			grant.Namespace = &namespace
		}
		result.Grants = append(result.Grants, grant)
	}
	if c.beforeReply != nil {
		c.beforeReply()
	}
	if c.alter {
		result.Grants[0].Operation = controlv1.ApplicationAllocate
	}
	if c.lost {
		c.lost = false
		return controlv1.RegisteredApplication{}, errors.New("reply lost after registration")
	}
	return result, nil
}

func registrationFixture(t *testing.T) (*clientstate.Database, *clientstate.Store, RegistrationSpec, string) {
	t.Helper()
	root := t.TempDir()
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(root, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store, err := database.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	url, service, domain := "url_"+strings.Repeat("U", 22), "svc_"+strings.Repeat("S", 22), "dom_"+strings.Repeat("D", 22)
	spec := RegistrationSpec{TeamID: "team", Name: "worker", Ownership: controlv1.RegisterApplicationMember, ExpiresIn: time.Hour, Grants: []controlv1.ApplicationGrantInput{{Operation: controlv1.ApplicationVisit, PublicUrlId: &url}, {Operation: controlv1.ApplicationPublish, PublicUrlId: &url}, {Operation: controlv1.ApplicationVisit, ServiceId: &service}, {Operation: controlv1.ApplicationAllocate, DomainId: &domain}}}
	return database, store, spec, filepath.Join(root, "credential.json")
}

func TestApplicationRegistrationResumesLostReplyWithExactKeyRequestAndExpiry(t *testing.T) {
	database, store, spec, output := registrationFixture(t)
	control := &registrationControl{lost: true}
	if _, err := RegisterApplication(t.Context(), store, control, output, spec); err == nil {
		t.Fatal("lost reply did not fail")
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("lost reply exported an unconfirmed credential")
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(filepath.Dir(output), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	store, err = reopened.Server(t.Context(), control.ControlURL())
	if err != nil {
		t.Fatal(err)
	}
	changed := spec
	changed.Name = "another"
	if _, err := RegisterApplication(t.Context(), store, control, output, changed); !errors.Is(err, ErrRegistrationConflict) {
		t.Fatal("retry replaced the captured registration request", err)
	}
	result, err := RegisterApplication(t.Context(), store, control, output, spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 2 || !reflect.DeepEqual(control.calls[0], control.calls[1]) {
		t.Fatal("lost-reply retry changed its key, grants, deadline or idempotency key")
	}
	file, err := credentialfile.Read(output)
	if err != nil || file.ClientID != result.ClientId || len(file.Grants) != 4 {
		t.Fatal("registration did not export one multi-operation identity", err)
	}
	private, err := file.Validate()
	if err != nil || base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) != control.calls[0].body.PublicKey {
		t.Fatal("retry exported a different signing key", err)
	}
	if again, err := RegisterApplication(t.Context(), store, control, output, spec); err != nil || again.ClientId != result.ClientId || len(control.calls) != 2 {
		t.Fatal("completed retry enrolled another identity", err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credential export is not private", err)
	}
}

func TestApplicationRegistrationCapturesReplyBeforeExportAndNeverReplacesAnotherFile(t *testing.T) {
	_, store, spec, output := registrationFixture(t)
	control := &registrationControl{beforeReply: func() {
		if err := os.WriteFile(output, []byte("another file"), 0600); err != nil {
			t.Error(err)
		}
	}}
	if _, err := RegisterApplication(t.Context(), store, control, output, spec); !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatal("registration overwrote a concurrent file", err)
	}
	if data, err := os.ReadFile(output); err != nil || string(data) != "another file" {
		t.Fatal("concurrent file changed", err)
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	control.beforeReply = func() { t.Error("captured registration was sent again") }
	if _, err := RegisterApplication(t.Context(), store, control, output, spec); err != nil || len(control.calls) != 1 {
		t.Fatal("export retry repeated a captured network effect", err)
	}
	file, err := credentialfile.Read(output)
	if err != nil {
		t.Fatal(err)
	}
	file.PrivateKey = base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)))
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if err := credentialfile.Write(output, file); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterApplication(t.Context(), store, control, output, spec); !errors.Is(err, credentialfile.ErrExists) {
		t.Fatal("completed retry replaced another signing identity", err)
	}
}

func TestApplicationRegistrationRejectsDifferentControlReplyWithoutLosingPendingKey(t *testing.T) {
	_, store, spec, output := registrationFixture(t)
	control := &registrationControl{alter: true}
	_, err := RegisterApplication(t.Context(), store, control, output, spec)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
		t.Fatal("different scope response lost its reporting classification", err)
	}
	control.alter = false
	if _, err := RegisterApplication(t.Context(), store, control, output, spec); err != nil {
		t.Fatal(err)
	}
	if len(control.calls) != 2 || !reflect.DeepEqual(control.calls[0], control.calls[1]) {
		t.Fatal("invalid response caused replacement key enrollment")
	}
}

func TestApplicationRegistrationConcurrentRetriesJoinOneCapturedIdentity(t *testing.T) {
	_, store, spec, output := registrationFixture(t)
	control := &registrationControl{}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			if _, err := RegisterApplication(t.Context(), store, control, output, spec); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if len(control.calls) != 1 {
		t.Fatal("concurrent setup created several registrations")
	}
}

func TestApplicationRegistrationExistingFilePreventsNewAuthority(t *testing.T) {
	_, store, spec, output := registrationFixture(t)
	if err := os.WriteFile(output, []byte("do not overwrite"), 0600); err != nil {
		t.Fatal(err)
	}
	control := &registrationControl{}
	if _, err := RegisterApplication(t.Context(), store, control, output, spec); !errors.Is(err, credentialfile.ErrExists) || len(control.calls) != 0 {
		t.Fatal("existing output caused a new remote identity", err)
	}
}

func TestApplicationRegistrationExpiredCapturedReplyNeverResetsLifetime(t *testing.T) {
	_, store, spec, output := registrationFixture(t)
	spec.ExpiresIn = time.Nanosecond
	control := &registrationControl{}
	for range 2 {
		if _, err := RegisterApplication(t.Context(), store, control, output, spec); !errors.Is(err, ErrRegistrationExpired) {
			t.Fatal("expired setup silently reset grant lifetime", err)
		}
	}
	if len(control.calls) != 1 {
		t.Fatal("expired captured reply caused another registration")
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired grant was exported as ready")
	}
}
