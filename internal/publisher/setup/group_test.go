package setup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type provisioningControl struct {
	scope             Scope
	publisher         controlv1.EnvironmentPublisher
	requests          []controlv1.CreateEnvironmentPublisherEnrollmentRequest
	issuanceKeys      []string
	keys              []ed25519.PublicKey
	lostReply         bool
	lostIssuanceReply bool
	issued            map[string]controlv1.CreateEnvironmentPublisherEnrollmentRequest
	spent             int
	wrongPublisher    bool
}

func (c *provisioningControl) CreateEnvironmentPublisherEnrollment(_ context.Context, project, environment, key string, request controlv1.CreateEnvironmentPublisherEnrollmentRequest) (controlv1.EnvironmentPublisherEnrollment, error) {
	if project != c.scope.Project || environment != c.scope.EnvironmentID || !opaqueid.Valid(key, opaqueid.IdempotencyPrefix) {
		return controlv1.EnvironmentPublisherEnrollment{}, credentialfile.ErrInvalid
	}
	c.requests = append(c.requests, request)
	c.issuanceKeys = append(c.issuanceKeys, key)
	if c.issued == nil {
		c.issued = map[string]controlv1.CreateEnvironmentPublisherEnrollmentRequest{}
	}
	if old, found := c.issued[key]; found {
		if !reflect.DeepEqual(old, request) {
			return controlv1.EnvironmentPublisherEnrollment{}, credentialfile.ErrInvalid
		}
	} else {
		c.issued[key] = request
		c.spent++
	}
	if c.lostIssuanceReply {
		c.lostIssuanceReply = false
		return controlv1.EnvironmentPublisherEnrollment{}, errors.New("issuance reply lost")
	}
	return controlv1.EnvironmentPublisherEnrollment{EnrollmentKey: "enrollment-test-only", MaxMembers: 1, ExpiresAt: time.Now().Add(time.Minute), Ref: controlv1.EnvironmentReference{Server: c.scope.Server, ProjectKey: project, EnvironmentId: environment}}, nil
}

func (c *provisioningControl) Enroll(_ context.Context, _ string, public ed25519.PublicKey) (controlv1.EnvironmentPublisher, error) {
	c.keys = append(c.keys, bytes.Clone(public))
	if c.lostReply {
		c.lostReply = false
		return controlv1.EnvironmentPublisher{}, errors.New("redemption reply lost")
	}
	return c.publisher, nil
}

func (c *provisioningControl) Verify(_ context.Context, publisher controlv1.EnvironmentPublisher, private ed25519.PrivateKey) (controlv1.EnvironmentPublisher, error) {
	if publisher != c.publisher || !bytes.Equal(private.Public().(ed25519.PublicKey), c.keys[0]) {
		return controlv1.EnvironmentPublisher{}, credentialfile.ErrInvalid
	}
	if c.wrongPublisher {
		publisher.EnvironmentId = "env_wrong"
	}
	return publisher, nil
}

func provisionFixture(t *testing.T) (*clientstate.Store, *provisioningControl) {
	t.Helper()
	newID := func(prefix string) string {
		id, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	profile, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Server: "https://control.example", Team: newID(opaqueid.TeamPrefix), Project: "project-one", EnvironmentID: newID(opaqueid.EnvironmentPrefix), Instance: "replica-1", MutationRevision: 7, ConfigurationHash: strings.Repeat("a", 64), Services: []string{"database"}}
	return profile, &provisioningControl{scope: scope, publisher: controlv1.EnvironmentPublisher{TeamId: scope.Team, ProjectKey: scope.Project, EnvironmentId: scope.EnvironmentID, PublisherIdentityId: newID(opaqueid.PublisherIdentityPrefix), KeyId: newID(opaqueid.PublisherIdentityKeyPrefix)}}
}

func TestEnvironmentProvisionKeepsKeyFenceAndAllowlistAfterLostReply(t *testing.T) {
	profile, control := provisionFixture(t)
	control.lostReply = true
	if _, err := Ensure(t.Context(), profile, control, control, control.scope); err == nil {
		t.Fatal("lost redemption reply was hidden")
	}
	changed := control.scope
	changed.MutationRevision++
	changed.ConfigurationHash = strings.Repeat("b", 64)
	changed.Services = []string{"database", "new-service"}
	value, err := Ensure(t.Context(), profile, control, control, changed)
	if err != nil {
		t.Fatal(err)
	}
	if len(control.requests) != 1 || len(control.keys) != 2 || !bytes.Equal(control.keys[0], control.keys[1]) {
		t.Fatal("retry replaced its protected key or issued a broader enrollment")
	}
	request := control.requests[0]
	if request.ExpectedRevision != control.scope.MutationRevision || request.ConfigurationHash != control.scope.ConfigurationHash || !reflect.DeepEqual(request.Services, control.scope.Services) {
		t.Fatal("enrollment lost its original application fence or fixed services")
	}
	again, err := Ensure(t.Context(), profile, control, control, changed)
	if err != nil || again != value || len(control.keys) != 2 || len(control.requests) != 1 {
		t.Fatal("exporting retained identity enrolled a new key", err)
	}
	if _, found, err := profile.ControlSession(t.Context()); err != nil || found {
		t.Fatal("provisioning created a hidden person session", err)
	}
}

func TestEnvironmentProvisionRejectsForeignVerificationWithoutFallback(t *testing.T) {
	profile, control := provisionFixture(t)
	value, err := Ensure(t.Context(), profile, control, control, control.scope)
	if err != nil {
		t.Fatal(err)
	}
	control.wrongPublisher = true
	if _, err := Ensure(t.Context(), profile, control, control, control.scope); err == nil {
		t.Fatal("foreign environment verification was accepted")
	}
	retained, found, err := credentialfile.SavedGroup(profile, value.ControlURL, value.Member.ProjectKey, value.Member.EnvironmentId, value.Instance)
	if err != nil || !found || retained != value || len(control.requests) != 1 || len(control.keys) != 1 {
		t.Fatal("invalid verification replaced authority or fell back to enrollment", err)
	}
}

func TestEnvironmentProvisionExpiredBootstrapRetainsOriginalAuthorizationIntent(t *testing.T) {
	profile, control := provisionFixture(t)
	control.lostReply = true
	if _, err := Ensure(t.Context(), profile, control, control, control.scope); err == nil {
		t.Fatal("lost redemption reply was hidden")
	}
	selection := credentialfile.GroupSelection(control.scope.Project, control.scope.EnvironmentID, control.scope.Instance)
	data, revision, err := profile.PublisherProvision(t.Context(), "group", selection)
	if err != nil {
		t.Fatal(err)
	}
	var pending journal
	if err := json.Unmarshal(data, &pending); err != nil {
		t.Fatal(err)
	}
	pending.ExpiresAt = time.Now().Add(-time.Minute)
	if err := save(t.Context(), profile, selection, &revision, pending); err != nil {
		t.Fatal(err)
	}
	broader := control.scope
	broader.MutationRevision++
	broader.ConfigurationHash = strings.Repeat("b", 64)
	broader.Services = []string{"database", "future-service"}
	control.lostIssuanceReply = true
	if _, err := Ensure(t.Context(), profile, control, control, broader); err == nil {
		t.Fatal("lost renewal issuance reply was hidden")
	}
	if _, err := Ensure(t.Context(), profile, control, control, broader); err != nil {
		t.Fatal(err)
	}
	if len(control.requests) != 3 || !reflect.DeepEqual(control.requests[0], control.requests[1]) || !reflect.DeepEqual(control.requests[1], control.requests[2]) || !bytes.Equal(control.keys[0], control.keys[1]) {
		t.Fatal("expired enrollment changed the key, application fence or fixed allowlist")
	}
	if control.spent != 2 || control.issuanceKeys[0] == control.issuanceKeys[1] || control.issuanceKeys[1] != control.issuanceKeys[2] {
		t.Fatal("renewal reply loss spent another enrollment budget or reused the expired intent")
	}
}

func TestEnvironmentProvisionLostIssuanceReplyKeepsPersistedBudgetIntent(t *testing.T) {
	profile, control := provisionFixture(t)
	control.lostIssuanceReply = true
	if _, err := Ensure(t.Context(), profile, control, control, control.scope); err == nil {
		t.Fatal("lost issuance reply was hidden")
	}
	selection := credentialfile.GroupSelection(control.scope.Project, control.scope.EnvironmentID, control.scope.Instance)
	data, _, err := profile.PublisherProvision(t.Context(), "group", selection)
	if err != nil {
		t.Fatal(err)
	}
	var pending journal
	if err := json.Unmarshal(data, &pending); err != nil {
		t.Fatal(err)
	}
	if len(control.issuanceKeys) != 1 || pending.IssuanceKey == "" || pending.IssuanceKey != control.issuanceKeys[0] || pending.Enrollment != "" || len(pending.Key) != ed25519.PrivateKeySize {
		t.Fatal("issuance key or private signing key was not durable before request")
	}
	broader := control.scope
	broader.MutationRevision++
	broader.ConfigurationHash = strings.Repeat("b", 64)
	broader.Services = []string{"database", "future-service"}
	value, err := Ensure(t.Context(), profile, control, control, broader)
	if err != nil {
		t.Fatal(err)
	}
	if control.spent != 1 || len(control.requests) != 2 || control.issuanceKeys[0] != control.issuanceKeys[1] || !reflect.DeepEqual(control.requests[0], control.requests[1]) {
		t.Fatal("lost issuance reply changed authorization intent or spent budget twice")
	}
	private, err := value.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.EnvironmentId, value.Instance)
	if err != nil || !bytes.Equal(private, pending.Key) {
		t.Fatal("issuance retry changed its protected signing key", err)
	}
}
