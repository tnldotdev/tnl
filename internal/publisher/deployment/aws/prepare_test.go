package awsbootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/testutil/awsfixture"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type provisionFixture struct {
	group         string
	members       map[string]controlv1.PublisherGroupMember
	keys          map[string]ed25519.PublicKey
	lost, revoked bool
	enrollments   int
}

func (f *provisionFixture) CreatePublisherGroupEnrollment(_ context.Context, _, _ string, _ controlv1.CreatePublisherGroupEnrollmentRequest) (controlv1.PublisherGroupEnrollment, error) {
	f.enrollments++
	return controlv1.PublisherGroupEnrollment{EnrollmentKey: "fixture-enrollment", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (f *provisionFixture) Enroll(_ context.Context, _ string, key ed25519.PublicKey) (controlv1.PublisherGroupMember, error) {
	m, found := f.members[string(key)]
	if !found {
		id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
		kid, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
		m = controlv1.PublisherGroupMember{PublisherIdentityId: id, KeyId: kid, TeamId: "team", ProjectKey: "shop", GroupId: f.group, GroupName: "production"}
		f.members[string(key)] = m
		f.keys[id] = key
	}
	if f.lost {
		f.lost = false
		return controlv1.PublisherGroupMember{}, errors.New("lost enrollment reply")
	}
	return m, nil
}
func (f *provisionFixture) Verify(_ context.Context, m controlv1.PublisherGroupMember, key ed25519.PrivateKey) (controlv1.PublisherGroupVerification, error) {
	if f.revoked || !key.Public().(ed25519.PublicKey).Equal(f.keys[m.PublisherIdentityId]) {
		return controlv1.PublisherGroupVerification{}, credentialfile.ErrInvalid
	}
	return controlv1.PublisherGroupVerification{Member: m, GroupNames: []string{"production", "renamed"}}, nil
}

func setup(t *testing.T) (Preparer, Request, *awsfixture.Fixture, *provisionFixture) {
	t.Helper()
	f := awsfixture.New(t)
	secrets, caller := f.Clients()
	if err := CheckAccount(t.Context(), caller, awsfixture.Account); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	db, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(root, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := db.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := clientstate.OpenPrivateDirectory(filepath.Join(root, ".tnl", "local", "aws"))
	if err != nil {
		t.Fatal(err)
	}
	group, _ := opaqueid.New("pgrp_")
	c := &provisionFixture{group: group, members: map[string]controlv1.PublisherGroupMember{}, keys: map[string]ed25519.PublicKey{}}
	r := Request{Binding: Binding{ControlOrigin: "https://control.example", TeamID: "team", ProjectKey: "shop", GroupID: group, SourceFingerprint: strings.Repeat("a", 64), AccountID: awsfixture.Account, Region: awsfixture.Region, DeploymentName: "production", ReplicaSlot: "replica-1"}, Group: "production"}
	return Preparer{Store: store, Secrets: secrets, Control: c, Client: c, Receipts: receipts}, r, f, c
}

func TestPrepareLostRepliesAndCrashTransitions(t *testing.T) {
	for _, boundary := range []string{"planned", "creating", "container", "enrolling", "enrolled", "putting", "durable", "CreateSecret", "PutSecretValue", "enroll"} {
		t.Run(boundary, func(t *testing.T) {
			p, r, f, c := setup(t)
			crash := errors.New("simulated process loss")
			p.afterSave = func(stage string) error {
				if stage == boundary {
					return crash
				}
				return nil
			}
			if boundary == "CreateSecret" || boundary == "PutSecretValue" {
				f.LoseReply(boundary)
			}
			if boundary == "enroll" {
				c.lost = true
			}
			if _, err := p.Prepare(t.Context(), r); err == nil {
				t.Fatal("interruption reported prepared")
			}
			p.afterSave = nil
			ref, err := p.Prepare(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
			calls := len(f.Calls())
			again, err := p.Prepare(t.Context(), r)
			if err != nil || again != ref {
				t.Fatal("retry changed references", err)
			}
			for _, call := range f.Calls()[calls:] {
				if call.Operation == "CreateSecret" || call.Operation == "PutSecretValue" {
					t.Fatal("ordinary retry wrote AWS state")
				}
			}
			if len(c.members) != 1 || c.enrollments != 1 {
				t.Fatal("retry enrolled another identity")
			}
			value, err := credentialfile.ParseGroup([]byte(f.Value(ref.SecretARN, ref.SecretVersion)))
			if err != nil || value.Member.PublisherIdentityId != ref.PublisherIdentityID {
				t.Fatal("prepared identity is not durable")
			}
			receipt, err := os.ReadFile(filepath.Join(p.Receipts.Path(), r.Binding.ID()+".json"))
			if err != nil || strings.Contains(string(receipt), value.PrivateKey) || strings.Contains(string(receipt), "private_key") {
				t.Fatal("receipt contains private key")
			}
			for _, call := range f.Calls() {
				if (call.Operation == "CreateSecret" || call.Operation == "PutSecretValue") && len(call.Token) != 64 {
					t.Fatal("mutation had no stable token")
				}
			}
		})
	}
}

func TestPrepareSlotsAndDeploymentBindings(t *testing.T) {
	p, r, _, c := setup(t)
	first, err := p.Prepare(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	other := r
	other.Binding.ReplicaSlot = "replica-2"
	second, err := p.Prepare(t.Context(), other)
	if err != nil {
		t.Fatal(err)
	}
	other.Binding.DeploymentName = "another"
	third, err := p.Prepare(t.Context(), other)
	if err != nil {
		t.Fatal(err)
	}
	if first.Instance == second.Instance || second.Instance == third.Instance || first.PublisherIdentityID == second.PublisherIdentityID || second.PublisherIdentityID == third.PublisherIdentityID || len(c.members) != 3 {
		t.Fatal("deployment or slot reused another key")
	}
	r.Group = "renamed"
	again, err := p.Prepare(t.Context(), r)
	if err != nil || again != first {
		t.Fatal("group rename changed binding", err)
	}
	for _, change := range []func(*Binding){func(b *Binding) { b.AccountID = "999999999999" }, func(b *Binding) { b.Region = "us-west-2" }} {
		b := r.Binding
		change(&b)
		if b.Instance() == r.Binding.Instance() {
			t.Fatal("AWS scope did not separate identity")
		}
	}
}

func TestPrepareRejectsForeignAndRevokedSecrets(t *testing.T) {
	for _, kind := range []string{"tags", "proof", "key", "scope", "version", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			p, r, f, c := setup(t)
			ref, err := p.Prepare(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
			data, revision, err := p.Store.PublisherProvision(t.Context(), "aws", r.Binding.ID())
			if err != nil {
				t.Fatal(err)
			}
			var j operation
			if json.Unmarshal(data, &j) != nil {
				t.Fatal("journal")
			}
			_ = revision
			f.Alter(ref.SecretARN, func(s *awsfixture.Secret) {
				switch kind {
				case "tags":
					s.Tags = nil
				case "proof":
					s.Versions[j.CreateToken] = "another operation"
				case "version":
					delete(s.Versions, ref.SecretVersion)
				case "scope", "key":
					v := *j.Identity
					if kind == "scope" {
						v.Member.GroupId = "pgrp_foreign"
					} else {
						_, key, err := ed25519.GenerateKey(rand.Reader)
						if err != nil {
							t.Fatal(err)
						}
						v, err = credentialfile.NewGroup(v.ControlURL, v.Instance, v.Member, key)
						if err != nil {
							t.Fatal(err)
						}
					}
					data, _ := json.Marshal(v)
					s.Versions[ref.SecretVersion] = string(data)
				}
			})
			if kind == "revoked" {
				c.revoked = true
			}
			before := len(f.Calls())
			if _, err := p.Prepare(t.Context(), r); err == nil {
				t.Fatal("foreign secret accepted")
			}
			for _, call := range f.Calls()[before:] {
				if call.Operation == "PutSecretValue" || call.Operation == "CreateSecret" {
					t.Fatal("foreign secret overwritten")
				}
			}
		})
	}
}

func TestExternalContainerLostPutAndExistingIdentity(t *testing.T) {
	p, r, f, c := setup(t)
	r.Secret.ExistingARN = f.Add("customer/container")
	f.LoseReply("PutSecretValue")
	if _, err := p.Prepare(t.Context(), r); err == nil {
		t.Fatal("lost response reported prepared")
	}
	ref, err := p.Prepare(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Ownership != "external" || c.enrollments != 1 {
		t.Fatal("external container ownership lost")
	}
	for _, call := range f.Calls() {
		if call.Operation == "CreateSecret" {
			t.Fatal("created external container")
		}
	}
	// an explicit existing identity on a fresh operator is read and verified,
	// without enrollment or mutations. a changed operation input is rejected.
	r.Secret.ExistingVersion = ref.SecretVersion
	r.Secret.PublisherIdentityID = ref.PublisherIdentityID
	if _, err := p.Prepare(t.Context(), r); err == nil {
		t.Fatal("changed existing operation input")
	}
	root := t.TempDir()
	db, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(root, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p.Store, err = db.Server(t.Context(), r.Binding.ControlOrigin)
	if err != nil {
		t.Fatal(err)
	}
	p.Receipts, err = clientstate.OpenPrivateDirectory(filepath.Join(root, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	if reused, err := p.Prepare(t.Context(), r); err != nil || reused != ref {
		t.Fatal("explicit pinned identity not reused", err)
	}
	if c.enrollments != 1 {
		t.Fatal("existing identity enrolled")
	}
}

func TestBootstrapProviderFailuresAndCancellation(t *testing.T) {
	p, r, f, c := setup(t)
	for code, reason := range map[string]failure.Reason{"AccessDeniedException": failure.AWSBootstrapDenied, "ExpiredTokenException": failure.AWSBootstrapAuthentication, "ThrottlingException": failure.AWSBootstrapThrottled, "InvalidRequestException": failure.AWSBootstrapVersionConflict} {
		f.Deny(code)
		_, err := p.Prepare(t.Context(), r)
		if actual, ok := failure.Of(err); !ok || actual.Reason() != reason {
			t.Fatalf("classification = %v", err)
		}
		definition, _ := failure.DefinitionFor(reason)
		if strings.Contains(definition.Message, "fixture-private") {
			t.Fatal("provider body escaped")
		}
	}
	f.Deny("")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.Prepare(ctx, r); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not preserved", err)
	}
	if c.enrollments != 0 {
		t.Fatal("failure enrolled a key")
	}
	_, caller := f.Clients()
	f.Account("999999999999")
	if err := CheckAccount(t.Context(), caller, awsfixture.Account); err == nil {
		t.Fatal("wrong AWS account accepted")
	}
}

func TestBootstrapLostStateNeverEnrollsReplacement(t *testing.T) {
	for _, kind := range []string{"journal", "owner", "key"} {
		t.Run(kind, func(t *testing.T) {
			p, r, f, c := setup(t)
			c.lost = true
			if _, err := p.Prepare(t.Context(), r); err == nil {
				t.Fatal("lost enrollment reply accepted")
			}
			before := len(f.Calls())
			if kind == "journal" || kind == "owner" {
				old := p.Store
				root := t.TempDir()
				db, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(root, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				p.Store, err = db.Server(t.Context(), r.Binding.ControlOrigin)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "owner" {
					data, _, err := old.PublisherProvision(t.Context(), "aws", r.Binding.ID())
					if err != nil {
						t.Fatal(err)
					}
					if err := p.Store.AppendPublisherProvision(t.Context(), "aws", r.Binding.ID(), 0, data); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				selection := credentialfile.GroupSelection(r.Binding.ProjectKey, r.Binding.GroupID, r.Binding.Instance())
				data, revision, err := p.Store.PublisherProvision(t.Context(), "group", selection)
				if err != nil {
					t.Fatal(err)
				}
				var document map[string]any
				if json.Unmarshal(data, &document) != nil {
					t.Fatal("owner journal")
				}
				delete(document, "Key")
				data, _ = json.Marshal(document)
				if err := p.Store.AppendPublisherProvision(t.Context(), "group", selection, revision, data); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.Prepare(t.Context(), r); err == nil {
				t.Fatal("lost state accepted")
			}
			if c.enrollments != 1 || len(c.members) != 1 {
				t.Fatal("lost state enrolled replacement")
			}
			for _, call := range f.Calls()[before:] {
				if call.Operation == "PutSecretValue" || call.Operation == "CreateSecret" {
					t.Fatal("lost state wrote secret")
				}
			}
		})
	}
}

func TestBootstrapForeignNamesAndExternalContainers(t *testing.T) {
	for _, external := range []bool{false, true} {
		p, r, f, c := setup(t)
		name := "tnl/publishers/" + r.Binding.Instance()
		arn := f.Add(name)
		if external {
			r.Secret.ExistingARN = arn
			f.Alter(arn, func(s *awsfixture.Secret) {
				s.Versions[strings.Repeat("b", 64)] = "foreign-key"
				s.Stages[strings.Repeat("b", 64)] = []string{"AWSCURRENT"}
			})
		}
		if _, err := p.Prepare(t.Context(), r); err == nil {
			t.Fatal("foreign container adopted")
		}
		if c.enrollments != 0 {
			t.Fatal("name collision enrolled a key")
		}
		for _, call := range f.Calls() {
			if call.Operation == "GetSecretValue" || call.Operation == "PutSecretValue" || call.Operation == "CreateSecret" {
				t.Fatal("foreign resource read or changed")
			}
		}
	}
}

func TestBootstrapCancelsInFlightWriteAndJoins(t *testing.T) {
	p, r, f, _ := setup(t)
	started := f.BlockOnce("PutSecretValue")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.Prepare(ctx, r); done <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("write did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("in-flight cancellation changed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bootstrap did not join cancelled request")
	}
	if _, err := p.Prepare(t.Context(), r); err != nil {
		t.Fatal("cancelled write could not resume", err)
	}
}

func TestBootstrapNetworkFailureKeepsPendingIntent(t *testing.T) {
	p, r, f, c := setup(t)
	f.Server.Close()
	_, err := p.Prepare(t.Context(), r)
	if reason, ok := failure.Of(err); !ok || reason.Reason() != failure.AWSBootstrapUnavailable {
		t.Fatal("network classification", err)
	}
	if c.enrollments != 0 {
		t.Fatal("unavailable AWS enrolled a key")
	}
}
