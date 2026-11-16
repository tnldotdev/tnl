package setup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	json "encoding/json/v2"
	"errors"
	"maps"
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
	t                                     *testing.T
	scope                                 Scope
	enrollment                            controlv1.DeploymentPublisherEnrollment
	member                                controlv1.DeploymentPublisherIdentity
	status                                controlv1.DeploymentPublisher
	statusErr, verifyErr                  error
	request                               string
	public                                ed25519.PublicKey
	createCalls, redeemCalls, statusCalls int
	loseCreate, loseRedeem, deny          bool
}

func (c *setupControl) GetDeploymentPublisher(_ context.Context, team, project, deployment, publisher string) (controlv1.DeploymentPublisher, error) {
	c.t.Helper()
	c.statusCalls++
	if team != c.scope.Team || project != c.scope.Project || deployment != c.scope.DeploymentID || publisher != c.member.PublisherIdentityId {
		c.t.Fatal("approval read changed the exact publisher selection")
	}
	return c.status, c.statusErr
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
	return controlv1.DeploymentPublisherVerification{Member: member, DeploymentNames: []string{member.DeploymentName}}, c.verifyErr
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
	c.status = controlv1.DeploymentPublisher{TeamId: scope.Team, ProjectKey: scope.Project, DeploymentId: scope.DeploymentID, DeploymentName: scope.Deployment, PublisherIdentityId: c.member.PublisherIdentityId, KeyId: c.member.KeyId, Services: maps.Clone(c.enrollment.Services)}
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

func seedSetupIdentity(t *testing.T, store *clientstate.Store, control *setupControl, source string) credentialfile.DeploymentFile {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	control.public = public
	scope := control.scope
	value, err := credentialfile.NewDeployment(scope.Server, scope.Instance, control.member, private)
	if err != nil {
		t.Fatal(err)
	}
	selection := credentialfile.DeploymentSelection(scope.Project, scope.DeploymentID, scope.Instance)
	switch source {
	case "retained":
		err = credentialfile.RetainDeployment(t.Context(), store, value)
	case "selected":
		_, err = credentialfile.ImportDeployment(t.Context(), store, value, scope.Server, scope.Project, scope.Deployment, scope.Instance)
	case "pending", "pending-without-result":
		pending := clientstate.PendingPublisherEnrollment{EnrollmentID: control.enrollment.EnrollmentId, SelectionKind: "project", SelectionKey: selection, PublicKey: public, SigningKey: private, EnrollmentSecret: []byte(control.enrollment.EnrollmentKey), ExpiresAt: time.Now().Add(time.Hour)}
		err = store.SavePendingPublisherEnrollment(t.Context(), pending)
		if err == nil && source == "pending" {
			var data []byte
			data, err = json.Marshal(control.member)
			if err == nil {
				err = store.RecordPublisherEnrollmentResult(t.Context(), pending.EnrollmentID, data)
			}
		}
	default:
		t.Fatal("unknown identity source")
	}
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSetupReusedPublisherRequiresExactAuthenticatedApproval(t *testing.T) {
	for _, source := range []string{"retained", "selected", "pending"} {
		t.Run(source, func(t *testing.T) {
			for _, tc := range []struct {
				name     string
				services []string
				change   func(*setupControl)
				wantErr  error
			}{
				{name: "matching", services: []string{"db", "api"}},
				{name: "subset", services: []string{"db"}, wantErr: credentialfile.ErrInvalid},
				{name: "superset", services: []string{"api", "db", "worker"}, wantErr: credentialfile.ErrInvalid},
				{name: "unapproved", services: []string{"api", "unapproved"}, wantErr: credentialfile.ErrInvalid},
				{name: "missing-approval", change: func(c *setupControl) { c.status.Services = nil }, wantErr: credentialfile.ErrInvalid},
				{name: "empty-approval", change: func(c *setupControl) { c.status.Services = map[string]controlv1.ServiceProtocol{} }, wantErr: credentialfile.ErrInvalid},
				{name: "missing-binding", change: func(c *setupControl) { delete(c.status.Services, "db") }, wantErr: credentialfile.ErrInvalid},
				{name: "invalid-protocol", change: func(c *setupControl) { c.status.Services["db"] = "ssh" }, wantErr: credentialfile.ErrInvalid},
				{name: "revoked", change: func(c *setupControl) { c.status.RevokedAt = new(time.Now()) }, wantErr: credentialfile.ErrInvalid},
				{name: "missing-publisher", change: func(c *setupControl) { c.statusErr = errLostReply }, wantErr: errLostReply},
				{name: "verification-denied", change: func(c *setupControl) { c.verifyErr = errLostReply }, wantErr: errLostReply},
				{name: "other-team", change: func(c *setupControl) { c.status.TeamId += "other" }, wantErr: credentialfile.ErrInvalid},
				{name: "other-project", change: func(c *setupControl) { c.status.ProjectKey = "other" }, wantErr: credentialfile.ErrInvalid},
				{name: "other-deployment", change: func(c *setupControl) { c.status.DeploymentId += "other" }, wantErr: credentialfile.ErrInvalid},
				{name: "other-publisher", change: func(c *setupControl) { c.status.PublisherIdentityId += "other" }, wantErr: credentialfile.ErrInvalid},
				{name: "other-key", change: func(c *setupControl) { c.status.KeyId += "other" }, wantErr: credentialfile.ErrInvalid},
			} {
				t.Run(tc.name, func(t *testing.T) {
					store, control := setupFixture(t)
					expected := seedSetupIdentity(t, store, control, source)
					original := control.status
					control.status.Services = maps.Clone(original.Services)
					if tc.change != nil {
						tc.change(control)
					}
					services := tc.services
					if services == nil {
						services = []string{"api", "db"}
					}
					value, err := Ensure(t.Context(), store, control, control, control.scope, services, func() error {
						t.Fatal("reuse reached enrollment preparation")
						return nil
					})
					if tc.wantErr != nil {
						if !errors.Is(err, tc.wantErr) || value != (credentialfile.DeploymentFile{}) {
							t.Fatal("unchecked approval exported a credential", err)
						}
					} else if err != nil || value != expected {
						t.Fatal("matching reuse replaced its identity", err)
					}
					if control.statusCalls != 1 || control.createCalls != 0 || control.redeemCalls != 0 {
						t.Fatal("reuse skipped authenticated approval or enrolled a publisher")
					}
					selection := credentialfile.DeploymentSelection(control.scope.Project, control.scope.DeploymentID, control.scope.Instance)
					if _, revision, err := store.PublisherProvision(t.Context(), "deployment", selection); err != nil || revision != 0 {
						t.Fatal("reuse pinned unchecked intent in a provisioning journal", err)
					}
					control.status, control.statusErr, control.verifyErr = original, nil, nil
					value, err = Ensure(t.Context(), store, control, control, control.scope, []string{"db", "api"})
					if err != nil || value != expected || control.createCalls != 0 || control.redeemCalls != 0 {
						t.Fatal("rejected reuse prevented recovery with the exact approval", err)
					}
				})
			}
		})
	}
}

func TestSetupReusedPublisherAcceptsAllServiceProtocols(t *testing.T) {
	for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.Tcp, controlv1.Postgres, controlv1.Mysql, controlv1.Kubernetes} {
		t.Run(string(protocol), func(t *testing.T) {
			store, control := setupFixture(t)
			expected := seedSetupIdentity(t, store, control, "retained")
			control.status.Services = map[string]controlv1.ServiceProtocol{"db": protocol}
			value, err := Ensure(t.Context(), store, control, control, control.scope, []string{"db"})
			if err != nil || value != expected || control.createCalls != 0 || control.redeemCalls != 0 {
				t.Fatal("reuse rejected a supported captured protocol or enrolled a publisher", err)
			}
		})
	}
}

func TestSetupDoesNotReplacePendingApprovalWithoutMember(t *testing.T) {
	store, control := setupFixture(t)
	expected := seedSetupIdentity(t, store, control, "pending-without-result")
	if _, err := Ensure(t.Context(), store, control, control, control.scope, []string{"api", "db"}); !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatal("pending key without authenticated scope accepted replacement approval", err)
	}
	if control.createCalls != 0 || control.redeemCalls != 0 || control.statusCalls != 0 {
		t.Fatal("pending approval was replaced or redeemed during provisioning")
	}
	selection := credentialfile.DeploymentSelection(control.scope.Project, control.scope.DeploymentID, control.scope.Instance)
	private, err := expected.Validate(control.scope.Server, control.scope.Project, control.scope.Deployment, control.scope.Instance)
	if err != nil {
		t.Fatal(err)
	}
	pending, found, err := store.PendingPublisherEnrollmentForSelection(t.Context(), "project", selection)
	if err != nil || !found || !bytes.Equal(pending.SigningKey, private) || string(pending.EnrollmentSecret) != control.enrollment.EnrollmentKey {
		t.Fatal("rejected provisioning changed pending enrollment recovery", err)
	}
	data, err := json.Marshal(control.member)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordPublisherEnrollmentResult(t.Context(), pending.EnrollmentID, data); err != nil {
		t.Fatal(err)
	}
	value, err := Ensure(t.Context(), store, control, control, control.scope, []string{"db", "api"})
	if err != nil || value != expected || control.createCalls != 0 || control.redeemCalls != 0 {
		t.Fatal("completed pending enrollment lost its original signing identity", err)
	}
}

func TestSetupJournalRechecksCurrentCapturedApproval(t *testing.T) {
	store, control := setupFixture(t)
	expected, err := Ensure(t.Context(), store, control, control, control.scope, []string{"api", "db"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*controlv1.DeploymentPublisher){
		func(p *controlv1.DeploymentPublisher) { p.Services = nil },
		func(p *controlv1.DeploymentPublisher) { p.RevokedAt = new(time.Now()) },
	} {
		original := control.status
		mutate(&control.status)
		if _, err := Ensure(t.Context(), store, control, control, control.scope, []string{"api", "db"}); !errors.Is(err, credentialfile.ErrInvalid) {
			t.Fatal("journal replaced the current authenticated approval", err)
		}
		control.status = original
	}
	value, err := Ensure(t.Context(), store, control, control, control.scope, []string{"db", "api"})
	if err != nil || value != expected || control.createCalls != 1 || control.redeemCalls != 1 || control.statusCalls != 4 {
		t.Fatal("approval checks replaced the journal's identity or enrollment", err)
	}
}

func TestSetupLostApprovalReadRetainsExactEnrollment(t *testing.T) {
	store, control := setupFixture(t)
	control.statusErr = errLostReply
	if _, err := Ensure(t.Context(), store, control, control, control.scope, []string{"api", "db"}); !errors.Is(err, errLostReply) {
		t.Fatal("lost approval read exported an unchecked credential", err)
	}
	public := bytes.Clone(control.public)
	control.statusErr = nil
	value, err := Ensure(t.Context(), store, control, control, control.scope, []string{"db", "api"})
	if err != nil || value.Member != control.member || !bytes.Equal(control.public, public) || control.createCalls != 1 || control.redeemCalls != 1 || control.statusCalls != 2 {
		t.Fatal("approval read retry replaced its enrollment or signing identity", err)
	}
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
