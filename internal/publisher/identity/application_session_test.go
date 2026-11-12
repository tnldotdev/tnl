package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type applicationSessionControl struct{ PublicURLControl }

func (applicationSessionControl) ControlURL() string { return "https://control.example" }

type applicationSessionAuthority struct {
	response                               authorityv1.MachinePublicationSession
	refresh                                func(context.Context) (authorityv1.MachinePublicationSession, error)
	exchange                               func(context.Context) (authorityv1.MachinePublicationSession, error)
	token                                  func(context.Context) (string, error)
	exchanges, refreshes, tokens, cleanups int
}

func (a *applicationSessionAuthority) ExchangeMachinePublication(ctx context.Context, _ authorityv1.MachinePublicationExchange) (authorityv1.MachinePublicationSession, error) {
	a.exchanges++
	if a.exchange != nil {
		return a.exchange(ctx)
	}
	return a.response, nil
}
func (a *applicationSessionAuthority) RefreshMachinePublication(ctx context.Context, _ string, _ authorityv1.MachinePublicationRefresh) (authorityv1.MachinePublicationSession, error) {
	a.refreshes++
	if a.refresh != nil {
		return a.refresh(ctx)
	}
	return a.response, nil
}
func (a *applicationSessionAuthority) ExchangePublisherAssertion(ctx context.Context, _, _, _ string, _ ed25519.PrivateKey) (string, error) {
	a.tokens++
	if a.token != nil {
		return a.token(ctx)
	}
	return "session-scoped-token", nil
}
func (a *applicationSessionAuthority) CleanupMachinePublication(context.Context, string, authorityv1.MachinePublicationCleanup) error {
	a.cleanups++
	return nil
}

func applicationSessionResponse() authorityv1.MachinePublicationSession {
	const suffix = "0123456789ABCDEFGHIJKL"
	return authorityv1.MachinePublicationSession{Id: "mps_" + suffix, AccessToken: "source-bound-token", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Minute), IdentityExpiresAt: time.Now().Add(5 * time.Minute), RenewAfter: time.Now().Add(30 * time.Second), Publisher: authorityv1.PublisherEnrollmentResult{ClientId: "pub_" + suffix, KeyId: "pkey_" + suffix, GrantId: "pgrant_" + suffix, TeamId: "tm_" + suffix, Kind: authorityv1.SavedPublicUrl, PublicUrlId: new("url_" + suffix)}}
}

func TestApplicationSessionRejectsInvalidExchangeFacts(t *testing.T) {
	for name, change := range map[string]func(*authorityv1.MachinePublicationSession){
		"session":   func(r *authorityv1.MachinePublicationSession) { r.Id = "mps_bad" },
		"publisher": func(r *authorityv1.MachinePublicationSession) { r.Publisher.ClientId = "pub_bad" },
		"key":       func(r *authorityv1.MachinePublicationSession) { r.Publisher.KeyId = "pkey_bad" },
		"grant":     func(r *authorityv1.MachinePublicationSession) { r.Publisher.GrantId = "pgrant_bad" },
		"team":      func(r *authorityv1.MachinePublicationSession) { r.Publisher.TeamId = "tm_bad" },
		"resource": func(r *authorityv1.MachinePublicationSession) {
			r.Publisher.PublicUrlId = new("url_1111111111111111111111")
		},
		"extra namespace":  func(r *authorityv1.MachinePublicationSession) { r.Publisher.Namespace = new("apps.example") },
		"service grant":    func(r *authorityv1.MachinePublicationSession) { r.Publisher.Kind = authorityv1.Service },
		"token type":       func(r *authorityv1.MachinePublicationSession) { r.TokenType = "wrong" },
		"empty token":      func(r *authorityv1.MachinePublicationSession) { r.AccessToken = "" },
		"token whitespace": func(r *authorityv1.MachinePublicationSession) { r.AccessToken = "bad token" },
		"token expiry":     func(r *authorityv1.MachinePublicationSession) { r.ExpiresAt = time.Now().Add(-time.Second) },
		"source expiry":    func(r *authorityv1.MachinePublicationSession) { r.IdentityExpiresAt = time.Now().Add(-time.Second) },
		"unbounded token":  func(r *authorityv1.MachinePublicationSession) { r.ExpiresAt = r.IdentityExpiresAt.Add(time.Second) },
		"missing renewal":  func(r *authorityv1.MachinePublicationSession) { r.RenewAfter = time.Time{} },
		"late renewal":     func(r *authorityv1.MachinePublicationSession) { r.RenewAfter = r.IdentityExpiresAt },
	} {
		t.Run(name, func(t *testing.T) {
			a := &applicationSessionAuthority{response: applicationSessionResponse()}
			resource := *a.response.Publisher.PublicUrlId
			change(&a.response)
			s, err := exchangeApplicationSession(t, t.Context(), applicationSessionControl{}, a, resource, "", "ivk_0123456789ABCDEFGHIJKL", "explicit-proof")
			reason, _ := failure.ReasonOf(err)
			if s != nil || reason != failure.ServerResponseInvalid || a.exchanges != 1 || a.tokens != 0 {
				t.Fatal("invalid exchange facts accepted", err)
			}
		})
	}
}

func TestApplicationSessionRefreshPinsIdentityAndLastDeadline(t *testing.T) {
	for name, change := range map[string]func(*authorityv1.MachinePublicationSession){
		"session":   func(r *authorityv1.MachinePublicationSession) { r.Id = "mps_1111111111111111111111" },
		"publisher": func(r *authorityv1.MachinePublicationSession) { r.Publisher.ClientId = "pub_1111111111111111111111" },
		"key":       func(r *authorityv1.MachinePublicationSession) { r.Publisher.KeyId = "pkey_1111111111111111111111" },
		"grant":     func(r *authorityv1.MachinePublicationSession) { r.Publisher.GrantId = "pgrant_1111111111111111111111" },
		"team":      func(r *authorityv1.MachinePublicationSession) { r.Publisher.TeamId = "tm_1111111111111111111111" },
		"resource": func(r *authorityv1.MachinePublicationSession) {
			r.Publisher.PublicUrlId = new("url_1111111111111111111111")
		},
		"source rollback": func(r *authorityv1.MachinePublicationSession) {
			r.IdentityExpiresAt = r.IdentityExpiresAt.Add(-time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := &applicationSessionAuthority{response: applicationSessionResponse()}
			s, err := exchangeApplicationSession(t, t.Context(), applicationSessionControl{}, a, *a.response.Publisher.PublicUrlId, "", "ivk_0123456789ABCDEFGHIJKL", "explicit-proof")
			if err != nil {
				t.Fatal(err)
			}
			before := s.identityExpiresAt
			change(&a.response)
			if err := s.Refresh(t.Context(), "fresh-proof"); err == nil || s.identityExpiresAt != before || a.exchanges != 1 || a.refreshes != 1 {
				t.Fatal("refresh replaced immutable authority or extended a failed lease", err)
			}
		})
	}
}

func TestApplicationSessionExpiredProofCannotRefreshOrMintToken(t *testing.T) {
	a := &applicationSessionAuthority{response: applicationSessionResponse()}
	s, err := exchangeApplicationSession(t, t.Context(), applicationSessionControl{}, a, *a.response.Publisher.PublicUrlId, "", "ivk_0123456789ABCDEFGHIJKL", "explicit-proof")
	if err != nil {
		t.Fatal(err)
	}
	s.identityExpiresAt = time.Now().Add(-time.Second)
	if err := s.Refresh(t.Context(), "fresh-proof"); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	if token, err := s.Publisher().Access(t.Context()); token != "" || !errors.Is(err, ErrScope) {
		t.Fatal("expired session minted authority", err)
	}
	if a.refreshes != 0 || a.tokens != 0 || a.exchanges != 1 {
		t.Fatal("expired session tried to restore authority")
	}
}

func TestApplicationSessionRefreshRejectsExpiryCrossedDuringRequest(t *testing.T) {
	a := &applicationSessionAuthority{response: applicationSessionResponse()}
	s, err := exchangeApplicationSession(t, t.Context(), applicationSessionControl{}, a, *a.response.Publisher.PublicUrlId, "", "ivk_0123456789ABCDEFGHIJKL", "explicit-proof")
	if err != nil {
		t.Fatal(err)
	}
	record, err := s.publication.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	clear(record.NativeKey)
	expectedDeadline := s.identityExpiresAt
	if record.OwnerExpiresAt.Before(expectedDeadline) {
		expectedDeadline = record.OwnerExpiresAt
	}
	a.refresh = func(ctx context.Context) (authorityv1.MachinePublicationSession, error) {
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(expectedDeadline) {
			t.Error("refresh did not inherit the earliest confirmed owner/authority deadline")
		}
		// deterministically cross the saved fence without a wall-clock sleep.
		s.identityExpiresAt = time.Now().Add(-time.Second)
		return a.response, nil
	}
	if err := s.Refresh(t.Context(), "fresh-proof"); err == nil || s.identityExpiresAt.After(time.Now()) {
		t.Fatal("late proof revived an expired lease", err)
	}
}

func TestApplicationSessionRefreshPreservesIndependentCanceledFailure(t *testing.T) {
	a := &applicationSessionAuthority{response: applicationSessionResponse()}
	s, err := exchangeApplicationSession(t, t.Context(), applicationSessionControl{}, a, *a.response.Publisher.PublicUrlId, "", "ivk_0123456789ABCDEFGHIJKL", "explicit-proof")
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("independent source request failure")
	a.refresh = func(context.Context) (authorityv1.MachinePublicationSession, error) {
		return authorityv1.MachinePublicationSession{}, errors.Join(context.Canceled, failure)
	}
	err = s.Refresh(t.Context(), "fresh-proof")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, failure) {
		t.Fatal("source refresh dropped an independent cause", err)
	}
}

func TestApplicationSessionFreshProofExtendsOnlyLivePinnedSession(t *testing.T) {
	a := &applicationSessionAuthority{response: applicationSessionResponse()}
	s, err := exchangeApplicationSession(t, t.Context(), applicationSessionControl{}, a, *a.response.Publisher.PublicUrlId, "", "ivk_0123456789ABCDEFGHIJKL", "explicit-proof")
	if err != nil {
		t.Fatal(err)
	}
	before := s.identityExpiresAt
	a.response.IdentityExpiresAt = before.Add(time.Minute)
	if err := s.Refresh(t.Context(), "fresh-proof"); err != nil || s.identityExpiresAt != a.response.IdentityExpiresAt || a.exchanges != 1 {
		t.Fatal("fresh proof did not extend the same live session", err)
	}
}

func TestApplicationSessionCanceledSuccessCannotAdvanceAuthority(t *testing.T) {
	for _, operation := range []string{"exchange", "refresh", "token"} {
		t.Run(operation, func(t *testing.T) {
			a := &applicationSessionAuthority{response: applicationSessionResponse()}
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			cause := errors.New("app operation stopped")
			if operation == "exchange" {
				a.exchange = func(context.Context) (authorityv1.MachinePublicationSession, error) {
					cancel(cause)
					return a.response, nil
				}
			}
			s, err := exchangeApplicationSession(t, ctx, applicationSessionControl{}, a, *a.response.Publisher.PublicUrlId, "", "ivk_0123456789ABCDEFGHIJKL", "explicit-proof")
			if operation == "exchange" {
				if s != nil || !errors.Is(err, cause) {
					t.Fatal("canceled exchange accepted a session", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			before := s.identityExpiresAt
			a.refresh = func(context.Context) (authorityv1.MachinePublicationSession, error) {
				cancel(cause)
				updated := a.response
				updated.IdentityExpiresAt = before.Add(time.Minute)
				return updated, nil
			}
			a.token = func(context.Context) (string, error) { cancel(cause); return "late-token", nil }
			if operation == "refresh" {
				err = s.Refresh(ctx, "fresh-proof")
			} else {
				var token string
				token, err = s.Publisher().Access(ctx)
				if token != "" {
					t.Fatal("canceled operation returned a token")
				}
			}
			if !errors.Is(err, cause) || s.identityExpiresAt != before {
				t.Fatal("canceled success changed confirmed authority", err)
			}
		})
	}
}

func TestApplicationSessionNamespaceDomainPinnedAndExpiredCleanupIndependent(t *testing.T) {
	a := &applicationSessionAuthority{response: applicationSessionResponse()}
	a.response.Publisher.Kind, a.response.Publisher.PublicUrlId = authorityv1.Namespace, nil
	a.response.Publisher.Namespace, a.response.Publisher.DomainId = new("apps.example"), new("dom_0123456789ABCDEFGHIJKL")
	s, err := exchangeApplicationSession(t, t.Context(), applicationSessionControl{}, a, "", "apps.example", "ivk_0123456789ABCDEFGHIJKL", "explicit-proof")
	if err != nil {
		t.Fatal(err)
	}
	a.response.Publisher.DomainId = new("dom_1111111111111111111111")
	if err := s.Refresh(t.Context(), "fresh-proof"); err == nil {
		t.Fatal("namespace refresh changed its domain authority")
	}
	s.identityExpiresAt = time.Now().Add(-time.Hour)
	if err := s.CleanupAllocation(t.Context()); err != nil {
		t.Fatal("source expiry disabled original-key cleanup", err)
	}
	if a.tokens != 0 || a.exchanges != 1 || a.refreshes != 1 || a.cleanups != 1 {
		t.Fatal("cleanup tried to restore serving authority")
	}
}

func exchangeApplicationSession(t *testing.T, ctx context.Context, control PublicURLControl, authority ApplicationSessionAuthority, resource, namespace, invocation, assertion string) (*ApplicationSession, error) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	owner, err := clientstate.OpenApplicationPublications(root, root, root, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	binding := clientstate.ApplicationPublicationBinding{ServerURL: control.ControlURL(), InvocationID: invocation, OwnerHash: strings.Repeat("1", 64), PID: os.Getpid(), Target: "http://127.0.0.1:3000", ConfigurationDigest: strings.Repeat("2", 64), RequestDigest: strings.Repeat("3", 64), ResourceID: resource, Namespace: namespace, SourceKind: "oidc", SourceMachineID: "mci_0123456789ABCDEFGHIJKL"}
	entry, err := owner.Publication(ctx, binding, time.Now().Add(time.Minute))
	if err != nil {
		return nil, err
	}
	return OpenApplicationSession(ctx, control, authority, entry, assertion)
}
