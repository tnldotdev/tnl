package setup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	json "encoding/json/v2"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var errLostReply = errors.New("setup reply lost")

type setupControl struct {
	t                            *testing.T
	scope                        Scope
	enrollment                   controlv1.DeploymentPublisherEnrollment
	member                       controlv1.DeploymentPublisherIdentity
	request                      string
	public                       ed25519.PublicKey
	createCalls, redeemCalls     int
	loseCreate, loseRedeem, deny bool
}

func (c *setupControl) CreateDeploymentPublisherEnrollment(_ context.Context, team, project, deployment, key string, body controlv1.CreateDeploymentPublisherEnrollmentRequest) (controlv1.DeploymentPublisherEnrollment, error) {
	c.t.Helper()
	c.createCalls++
	if team != c.scope.Team || project != c.scope.Project || deployment != c.scope.DeploymentID || !opaqueid.Valid(key, opaqueid.IdempotencyPrefix) || !reflect.DeepEqual(body.Services, []string{"api", "db"}) || body.MaxMembers == nil || *body.MaxMembers != 1 {
		c.t.Fatal("setup changed exact approval intent")
	}
	if c.request != "" && key != c.request {
		c.t.Fatal("lost setup reply used a new operation key")
	}
	c.request = key
	if c.loseCreate {
		c.loseCreate = false
		return controlv1.DeploymentPublisherEnrollment{}, errLostReply
	}
	return c.enrollment, nil
}

func (c *setupControl) Enroll(_ context.Context, secret string, public ed25519.PublicKey) (controlv1.DeploymentPublisherIdentity, error) {
	c.t.Helper()
	c.redeemCalls++
	if secret != c.enrollment.EnrollmentKey || c.public != nil && !bytes.Equal(c.public, public) {
		c.t.Fatal("retry changed the original enrollment or signing key")
	}
	c.public = bytes.Clone(public)
	if c.deny {
		return controlv1.DeploymentPublisherIdentity{}, errLostReply
	}
	if c.loseRedeem {
		c.loseRedeem = false
		return controlv1.DeploymentPublisherIdentity{}, errLostReply
	}
	return c.member, nil
}

func (c *setupControl) Verify(_ context.Context, member controlv1.DeploymentPublisherIdentity, private ed25519.PrivateKey) (controlv1.DeploymentPublisherVerification, error) {
	c.t.Helper()
	if member != c.member || !bytes.Equal(private.Public().(ed25519.PublicKey), c.public) {
		c.t.Fatal("setup imported another signing identity")
	}
	return controlv1.DeploymentPublisherVerification{Member: member, DeploymentNames: []string{member.DeploymentName}}, nil
}

func setupFixture(t *testing.T) (*clientstate.Store, *setupControl) {
	t.Helper()
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	scope := Scope{Server: "https://control.example", Team: id(opaqueid.TeamPrefix), Project: "shop", DeploymentID: id("dpl_"), Deployment: "production", Instance: "replica"}
	c := &setupControl{t: t, scope: scope}
	enrollmentID := id(opaqueid.PublisherEnrollmentPrefix)
	c.enrollment = controlv1.DeploymentPublisherEnrollment{EnrollmentId: enrollmentID, EnrollmentKey: enrollmentID + ".private", DeploymentId: scope.DeploymentID, MaxMembers: 1, ExpiresAt: time.Now().Add(time.Hour), Services: map[string]controlv1.ServiceProtocol{"api": controlv1.ServiceProtocolHTTP, "db": controlv1.Postgres}}
	c.member = controlv1.DeploymentPublisherIdentity{TeamId: scope.Team, ProjectKey: scope.Project, DeploymentId: scope.DeploymentID, DeploymentName: scope.Deployment, PublisherIdentityId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix)}
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	store, err := state.Server(t.Context(), scope.Server)
	if err != nil {
		t.Fatal(err)
	}
	return store, c
}

func TestSetupLostRepliesRetainExactApprovalAndSigningKey(t *testing.T) {
	store, control := setupFixture(t)
	control.loseCreate, control.loseRedeem = true, true
	for range 2 {
		if _, err := Ensure(t.Context(), store, control, control, control.scope, []string{"db", "api"}); !errors.Is(err, errLostReply) {
			t.Fatal("lost reply did not remain retryable", err)
		}
	}
	value, err := Ensure(t.Context(), store, control, control, control.scope, []string{"api", "db"})
	if err != nil || value.Member != control.member || control.createCalls != 2 || control.redeemCalls != 2 {
		t.Fatal("recovery replaced approval or membership", err)
	}
	repeated, err := Ensure(t.Context(), store, control, control, control.scope, []string{"db", "api"})
	if err != nil || repeated != value || control.createCalls != 2 || control.redeemCalls != 2 {
		t.Fatal("export retry re-enrolled its publisher", err)
	}
	if _, err := Ensure(t.Context(), store, control, control, control.scope, []string{"db"}); !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatal("existing journal accepted changed service intent", err)
	}
}

func TestSetupDoesNotReplaceAnUnusableApproval(t *testing.T) {
	store, control := setupFixture(t)
	control.deny = true
	for range 2 {
		if _, err := Ensure(t.Context(), store, control, control, control.scope, []string{"api", "db"}); !errors.Is(err, errLostReply) {
			t.Fatal("denied enrollment was replaced", err)
		}
	}
	if control.createCalls != 1 || control.redeemCalls != 2 {
		t.Fatal("setup reissued approval after a redemption failure")
	}
	selection := credentialfile.DeploymentSelection(control.scope.Project, control.scope.DeploymentID, control.scope.Instance)
	data, revision, err := store.PublisherProvision(t.Context(), "deployment", selection)
	var saved journal
	if err != nil || json.Unmarshal(data, &saved) != nil {
		t.Fatal("missing durable setup intent", err)
	}
	saved.ExpiresAt = time.Now().Add(-time.Minute)
	if err := save(t.Context(), store, selection, &revision, saved); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(t.Context(), store, control, control, control.scope, []string{"api", "db"}); !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatal("expired approval remained usable", err)
	}
	if control.createCalls != 1 || control.redeemCalls != 2 {
		t.Fatal("expired approval triggered enrollment or replacement")
	}
}

func TestSetupRejectsMissingOrDuplicateBindingsBeforeState(t *testing.T) {
	for _, services := range [][]string{nil, {"api", "api"}, {"not a label"}} {
		if _, err := Ensure(t.Context(), nil, nil, nil, Scope{}, services); !errors.Is(err, credentialfile.ErrInvalid) {
			t.Fatal("invalid approval reached state or control", err)
		}
	}
}
