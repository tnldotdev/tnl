package publisher

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type browserTokenClientFixture struct {
	calls atomic.Int64
	issue func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error)
}

func TestBrowserTokensRedemptionWaitsForConcurrentPolicyWithoutReissuingPermission(t *testing.T) {
	for _, share := range []bool{false, true} {
		t.Run(map[bool]string{false: "browser", true: "share"}[share], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
				client := &policyClientFixture{key: key}
				blocked, release := context.WithCancel(t.Context())
				defer release()
				started := make(chan struct{})
				var reads atomic.Int64
				provider := policyClientFunc(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
					n := reads.Add(1)
					client.revision.Store(n)
					update, err := client.ReadPublisherVisitorPolicy(ctx, body, token)
					if n == 2 {
						close(started)
						select {
						case <-blocked.Done():
						case <-ctx.Done():
							return controlv1.VisitorPolicyUpdate{}, context.Cause(ctx)
						}
					}
					return update, err
				})
				scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
				policy, err := prepareVisitorPolicy(t.Context(), provider, scope, "run", 1, "run-secret", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer policy.Close()
				issuer := &browserTokenClientFixture{issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
					return controlv1.VisitorTokenResponse{}, errors.New("preparation must not reissue permission")
				}}
				tokens, err := startBrowserTokens(t.Context(), issuer, policy.lease, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tokens.Close()
				source := browserSourceFixture(liveBrowserCookie)
				var subject visitortoken.Subject = visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("C", 22), SessionID: "cs_" + strings.Repeat("D", 22)}
				if share {
					id := "shr_" + strings.Repeat("S", 22)
					subject = visitortoken.Share{ShareID: id}
					source, err = json.Marshal(controlv1.VisitorTokenShareSessionSource{Kind: controlv1.VisitorTokenShareSession, ShareId: id, Secret: liveBrowserCookie})
					if err != nil {
						t.Fatal(err)
					}
				}
				view, _, _ := policy.lease.Current()
				permission := visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: 3, Subject: subject, ExpiresAt: time.Now().Add(time.Minute).Truncate(time.Second)}
				signed, err := visitortoken.Sign(view.Issuer, "test-key", key, permission, view.AuthorityTime(time.Now()))
				if err != nil {
					t.Fatal(err)
				}
				response := controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: scope.ID}, Hostname: view.Hostname, Port: int(view.Port),
					VisitorToken: signed.Reveal(), VisitorPolicyRevision: 3, ExpiresAt: permission.ExpiresAt}
				refresh, prepared := make(chan error, 1), make(chan error, 1)
				go func() { refresh <- policy.refresh(t.Context()) }()
				<-started
				access := &browserAccess{policy: policy, tokens: tokens}
				go func() { prepared <- access.prepareToken(t.Context(), source, response, permission.ExpiresAt) }()
				synctest.Wait()
				if reads.Load() != 2 {
					t.Error("redemption raced another stale policy request", reads.Load())
				}
				release()
				if err := <-refresh; err != nil {
					t.Error("concurrent refresh failed", err)
				}
				if err := <-prepared; err != nil {
					t.Error("redeemed permission could not be installed", err)
				}
				if len(tokens.sources) != 1 || len(tokens.tokens) != 1 || issuer.calls.Load() != 0 || reads.Load() != 3 {
					t.Fatal("preparation repeated credential issuance or lost its local source", issuer.calls.Load(), reads.Load())
				}
			})
		})
	}
}

func TestBrowserTokensRenewalErrorsCannotExtendOrRestorePermission(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		terminal bool
	}{
		{"outage", clientcontrol.ErrUnavailable, false},
		{"cancellation", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
		{"unauthenticated", clientcontrol.ErrUnauthenticated, true},
		{"forbidden", &clientcontrol.ProblemError{Status: http.StatusForbidden}, true},
		{"malformed response", nil, true},
		{"invalid authority response", errors.New("invalid authority response"), true},
		{"invalid wire response", failure.Wrap("decode renewal", failure.ServerResponseInvalid, errors.New("invalid response")), true},
		{"invalid wire response wrapping deadline", failure.Wrap("decode renewal", failure.ServerResponseInvalid, context.DeadlineExceeded), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				policy, key, subject := browserTokensFixture(t)
				client := &browserTokenClientFixture{issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
					return controlv1.VisitorTokenResponse{VisitorToken: "malformed"}, test.err
				}}
				tokens, err := startBrowserTokens(t.Context(), client, policy.lease, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tokens.Close()
				initial := signedBrowserPermission(t, policy, key, subject, time.Now().Add(5*time.Minute))
				if err := tokens.install(browserSourceFixture(liveBrowserCookie), initial, time.Now().Add(30*time.Minute)); err != nil {
					t.Fatal(err)
				}
				token := visitortoken.Token(initial.VisitorToken)
				r := permissionRequest()
				r.Header.Set(visitorTokenHeader, token.Reveal())
				permission, err := localHTTPPermission(r, policy.lease, tokens)
				if err != nil {
					t.Fatal(err)
				}
				var stopped atomic.Int64
				guard, err := permission.bind(policy.lease, func() { stopped.Add(1) })
				if err != nil {
					t.Fatal(err)
				}
				defer guard.Close()
				_, release, found := tokens.use(token, guard)
				if !found {
					t.Fatal("redeemed source was not prepared")
				}
				defer release()
				time.Sleep(4*time.Minute + 4*time.Second)
				synctest.Wait()
				if client.calls.Load() == 0 {
					t.Fatal("background renewal did not run")
				}
				if test.terminal {
					if stopped.Load() != 1 {
						t.Fatal("explicit denial retained its active request")
					}
					if _, err := localHTTPPermission(r, policy.lease, tokens); err == nil {
						t.Fatal("denied source reused its still-signed token")
					}
					if !tokens.rejects(token) {
						t.Fatal("background cleanup discarded a live denial fence")
					}
				} else {
					current, done, found := tokens.use(token, nil)
					done()
					if !found || !current.ExpiresAt.Equal(initial.ExpiresAt) || stopped.Load() != 0 {
						t.Fatal("renewal failure changed the last signed authority")
					}
				}
				time.Sleep(time.Minute)
				synctest.Wait()
				if stopped.Load() != 1 {
					t.Fatal("renewal failure extended the token deadline")
				}
				if _, err := localHTTPPermission(r, policy.lease, tokens); err == nil {
					t.Fatal("expired token became a replacement handle")
				}
			})
		})
	}
}

func TestBrowserTokensRenewalWaitsForSignedPolicyRevision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, key, subject := browserTokensFixture(t)
		view, _, _ := policy.lease.Current()
		facts := visitortoken.Permission{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: 2, Subject: subject, ExpiresAt: time.Now().Add(5 * time.Minute)}
		signed, err := visitortoken.Sign(view.Issuer, "test-key", key, facts, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		response := controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: view.Scope.ID}, Hostname: view.Hostname, Port: int(view.Port), VisitorToken: signed.Reveal(), VisitorPolicyRevision: 2, ExpiresAt: facts.ExpiresAt}
		client := &browserTokenClientFixture{issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			return response, nil
		}}
		tokens, err := startBrowserTokens(t.Context(), client, policy.lease, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tokens.Close()
		source, parent := browserSourceFixture(liveBrowserCookie), time.Now().Add(30*time.Minute)
		initial := signedBrowserPermission(t, policy, key, subject, time.Now().Add(4*time.Minute))
		if err := tokens.install(source, initial, parent); err != nil {
			t.Fatal(err)
		}
		entry := tokens.sources[sha256.Sum256(source)]
		job := browserTokenRenewal{key: sha256.Sum256(source), source: entry, generation: entry.generation, request: controlv1.VisitorTokenRequest{Resource: initial.Resource, Source: source}, permission: entry.permission, parentDeadline: parent}
		token := visitortoken.Token(initial.VisitorToken)
		var reported error
		tokens.renew(t.Context(), job, func(err error) { reported = err })
		current, done, found := tokens.use(token, nil)
		done()
		if !errors.Is(reported, visitortoken.ErrPolicy) || tokens.rejects(token) || !found || current.VisitorToken != initial.VisitorToken {
			t.Fatal("pending policy revision revoked or replaced confirmed authority", reported)
		}
		policy.client.(*policyClientFixture).revision.Store(2)
		if err := policy.refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		tokens.renew(t.Context(), job, func(err error) { t.Error(err) })
		current, done, found = tokens.use(token, nil)
		done()
		if !found || current.VisitorToken != response.VisitorToken || tokens.rejects(token) {
			t.Fatal("installed policy did not allow same-source renewal")
		}
	})
}

func TestBrowserTokensRequestCancellationIsLocalAndCloseJoinsRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, key, subject := browserTokensFixture(t)
		started, cleanup, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		client := &browserTokenClientFixture{issue: func(ctx context.Context, _ controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			close(started)
			<-ctx.Done()
			close(cleanup)
			<-release
			return controlv1.VisitorTokenResponse{}, ctx.Err()
		}}
		tokens, err := startBrowserTokens(t.Context(), client, policy.lease, nil)
		if err != nil {
			t.Fatal(err)
		}
		initial := signedBrowserPermission(t, policy, key, subject, time.Now().Add(5*time.Minute))
		if err := tokens.install(browserSourceFixture(liveBrowserCookie), initial, time.Now().Add(30*time.Minute)); err != nil {
			t.Fatal(err)
		}
		var guards []*publicHTTPGuard
		var requests []*http.Request
		for range 2 {
			r := permissionRequest()
			r.Header.Set(visitorTokenHeader, initial.VisitorToken)
			permission, err := localHTTPPermission(r, policy.lease, tokens)
			if err != nil {
				t.Fatal(err)
			}
			guard, bound, err := guardLocalHTTPRequest(httptest.NewRecorder(), r, policy.lease, permission)
			if err != nil {
				t.Fatal(err)
			}
			_, guard.release, _ = tokens.use(visitortoken.Token(initial.VisitorToken), guard.local)
			guards, requests = append(guards, guard), append(requests, bound)
		}
		time.Sleep(4*time.Minute + time.Millisecond)
		<-started
		guards[0].finish()
		synctest.Wait()
		if !errors.Is(requests[0].Context().Err(), context.Canceled) || requests[1].Context().Err() != nil {
			t.Fatal("request cancellation crossed a sibling request boundary")
		}
		select {
		case <-cleanup:
			t.Fatal("request cancellation stopped background renewal")
		default:
		}
		closed := make(chan struct{})
		go func() { tokens.Close(); close(closed) }()
		<-cleanup
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("close returned before joining issuer cleanup")
		default:
		}
		close(release)
		<-closed
		if len(tokens.sources) != 0 || len(tokens.tokens) != 0 {
			t.Fatal("closed renewal retained source credentials")
		}
		guards[1].finish()
	})
}

func TestBrowserTokensLateRenewalCannotReplaceNewRedemption(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, key, subject := browserTokensFixture(t)
		started, release := make(chan struct{}), make(chan struct{})
		initial := signedBrowserPermission(t, policy, key, subject, time.Now().Add(4*time.Minute))
		client := &browserTokenClientFixture{issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			close(started)
			<-release
			return initial, nil
		}}
		tokens, err := startBrowserTokens(t.Context(), client, policy.lease, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tokens.Close()
		source, parent := browserSourceFixture(liveBrowserCookie), time.Now().Add(30*time.Minute)
		if err := tokens.install(source, initial, parent); err != nil {
			t.Fatal(err)
		}
		entry := tokens.sources[sha256.Sum256(source)]
		job := browserTokenRenewal{key: sha256.Sum256(source), source: entry, generation: entry.generation, request: controlv1.VisitorTokenRequest{Resource: initial.Resource, Source: source}, permission: entry.permission, parentDeadline: parent}
		done := make(chan struct{})
		go func() { tokens.renew(t.Context(), job, nil); close(done) }()
		<-started
		latest := signedBrowserPermission(t, policy, key, subject, time.Now().Add(5*time.Minute))
		if err := tokens.install(source, latest, parent); err != nil {
			t.Fatal(err)
		}
		close(release)
		<-done
		current, finish, found := tokens.use(visitortoken.Token(initial.VisitorToken), nil)
		finish()
		if !found || current.VisitorToken != latest.VisitorToken {
			t.Fatal("late renewal overwrote a newer explicit redemption")
		}
	})
}

func (f *browserTokenClientFixture) IssueVisitorToken(ctx context.Context, body controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	f.calls.Add(1)
	return f.issue(ctx, body)
}

func browserTokensFixture(t *testing.T) (*visitorPolicy, ed25519.PrivateKey, visitortoken.Browser) {
	t.Helper()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
	client := &policyClientFixture{key: key}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
	policy, err := prepareVisitorPolicy(t.Context(), client, scope, "pr_"+strings.Repeat("B", 22), 1, "run-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	return policy, key, visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("C", 22), SessionID: "cs_" + strings.Repeat("D", 22)}
}

func signedBrowserPermission(t *testing.T, policy *visitorPolicy, key ed25519.PrivateKey, subject visitortoken.Browser, until time.Time) controlv1.VisitorTokenResponse {
	t.Helper()
	view, enabled, _ := policy.lease.Current()
	if !enabled {
		t.Fatal("browser token fixture lost policy")
	}
	permission := visitortoken.Permission{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: subject, ExpiresAt: until.Truncate(time.Second)}
	token, err := visitortoken.Sign(view.Issuer, "test-key", key, permission, view.AuthorityTime(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	return controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: view.Scope.ID}, Hostname: view.Hostname, Port: int(view.Port),
		VisitorToken: token.Reveal(), VisitorPolicyRevision: view.VisitorPolicyRevision, ExpiresAt: permission.ExpiresAt}
}

func browserSourceFixture(secret string) json.RawMessage {
	source, _ := json.Marshal(controlv1.VisitorTokenBrowserSessionSource{Kind: controlv1.VisitorTokenBrowserSession, Secret: secret})
	return source
}

func TestBrowserTokensSessionExchangeCannotAdvanceKnownParentOrChangeSubject(t *testing.T) {
	policy, key, subject := browserTokensFixture(t)
	client := &browserTokenClientFixture{issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
		return controlv1.VisitorTokenResponse{}, clientcontrol.ErrUnavailable
	}}
	tokens, err := startBrowserTokens(t.Context(), client, policy.lease, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tokens.Close()
	source, parent := browserSourceFixture(liveBrowserCookie), time.Now().Add(2*time.Minute).Truncate(time.Second)
	initial := signedBrowserPermission(t, policy, key, subject, parent)
	if err := tokens.install(source, initial, parent); err != nil {
		t.Fatal(err)
	}
	if err := tokens.installFromSession(source, signedBrowserPermission(t, policy, key, subject, parent.Add(time.Minute))); err == nil {
		t.Fatal("session exchange advanced a known parent deadline")
	}
	subject.SessionID = "cs_" + strings.Repeat("Z", 22)
	if err := tokens.installFromSession(source, signedBrowserPermission(t, policy, key, subject, parent)); err == nil {
		t.Fatal("session exchange changed its verified subject")
	}
	current, release, found := tokens.use(visitortoken.Token(initial.VisitorToken), nil)
	defer release()
	if !found || current.VisitorToken != initial.VisitorToken {
		t.Fatal("rejected session evidence replaced the prior permission")
	}
}

func TestBrowserTokensBackgroundRenewalDoesNotAddRequestRPCs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, key, subject := browserTokensFixture(t)
		client := &browserTokenClientFixture{issue: func(_ context.Context, body controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			if strings.Contains(string(body.Source), "control_session") {
				return controlv1.VisitorTokenResponse{}, errors.New("renewal tried a management identity")
			}
			return signedBrowserPermission(t, policy, key, subject, time.Now().Add(5*time.Minute)), nil
		}}
		tokens, err := startBrowserTokens(t.Context(), client, policy.lease, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tokens.Close()
		initial := signedBrowserPermission(t, policy, key, subject, time.Now().Add(5*time.Minute))
		if err := tokens.install(browserSourceFixture(liveBrowserCookie), initial, time.Now().Add(30*time.Minute)); err != nil {
			t.Fatal(err)
		}
		for range 100 {
			_, release, found := tokens.use(visitortoken.Token(initial.VisitorToken), nil)
			if !found {
				t.Fatal("redeemed token lost its renewal owner")
			}
			release()
		}
		if client.calls.Load() != 0 {
			t.Fatal("using a prepared browser token made an issuer request")
		}
		view, _, _ := policy.lease.Current()
		permission, err := visitortoken.VerifyBearer(visitortoken.Token(initial.VisitorToken), view, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Int64
		guard, err := policy.lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		_, release, found := tokens.use(visitortoken.Token(initial.VisitorToken), guard)
		if !found {
			t.Fatal("active request did not retain its exact source")
		}
		defer release()
		time.Sleep(4*time.Minute + 2*time.Second)
		synctest.Wait()
		current, done, found := tokens.use(visitortoken.Token(initial.VisitorToken), nil)
		done()
		if !found || !current.ExpiresAt.After(initial.ExpiresAt) || client.calls.Load() != 1 {
			t.Fatal("browser token did not renew in the background")
		}
		var laterStopped atomic.Int64
		laterGuard, err := policy.lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { laterStopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer laterGuard.Close()
		_, laterRelease, found := tokens.use(visitortoken.Token(initial.VisitorToken), laterGuard)
		if !found {
			t.Fatal("request arriving after renewal lost its source")
		}
		defer laterRelease()
		time.Sleep(time.Minute)
		synctest.Wait()
		if stopped.Load() != 0 || laterStopped.Load() != 0 {
			t.Fatal("renewed same-subject request stopped at the replaced token deadline")
		}
		if _, done, found := tokens.use(visitortoken.Token(initial.VisitorToken), nil); found {
			done()
			t.Fatal("expired cookie selected a prepared replacement credential")
		}
	})
}

func TestBrowserTokensDeniedRenewalStopsOnlyItsSource(t *testing.T) {
	for _, test := range []struct {
		name        string
		sameSubject bool
	}{{"different-subjects", false}, {"same-subject", true}} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				policy, key, first := browserTokensFixture(t)
				second := first
				if !test.sameSubject {
					second.IdentityID, second.SessionID = "ident_"+strings.Repeat("E", 22), "cs_"+strings.Repeat("F", 22)
				}
				client := &browserTokenClientFixture{issue: func(_ context.Context, body controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
					var source controlv1.VisitorTokenBrowserSessionSource
					if json.Unmarshal(body.Source, &source) != nil || source.Secret == liveBrowserCookie {
						return controlv1.VisitorTokenResponse{}, &clientcontrol.ProblemError{Status: http.StatusForbidden}
					}
					return signedBrowserPermission(t, policy, key, second, time.Now().Add(5*time.Minute)), nil
				}}
				tokens, err := startBrowserTokens(t.Context(), client, policy.lease, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tokens.Close()
				var stopped [2]atomic.Int64
				var supplied [2]controlv1.VisitorTokenResponse
				for index, subject := range []visitortoken.Browser{first, second} {
					secret := liveBrowserCookie
					if index == 1 {
						secret = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
					}
					response := signedBrowserPermission(t, policy, key, subject, time.Now().Add(5*time.Minute))
					supplied[index] = response
					if err := tokens.install(browserSourceFixture(secret), response, time.Now().Add(30*time.Minute)); err != nil {
						t.Fatal(err)
					}
					view, _, _ := policy.lease.Current()
					permission, err := visitortoken.VerifyBearer(visitortoken.Token(response.VisitorToken), view, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					guard, err := policy.lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { stopped[index].Add(1) })
					if err != nil {
						t.Fatal(err)
					}
					defer guard.Close()
					_, release, found := tokens.use(visitortoken.Token(response.VisitorToken), guard)
					if !found {
						t.Fatal("source was not registered")
					}
					defer release()
				}
				policy.client.(*policyClientFixture).revision.Store(2)
				time.Sleep(4*time.Second + time.Millisecond)
				synctest.Wait()
				if stopped[0].Load() != 1 || stopped[1].Load() != 0 {
					t.Fatal("terminal authority result affected another browser source")
				}
				for index, response := range supplied {
					request := permissionRequest()
					request.Header.Set(visitorTokenHeader, response.VisitorToken)
					permission, err := localHTTPPermission(request, policy.lease, tokens)
					if index == 0 && err == nil {
						t.Fatal("revoked browser selected another prepared credential")
					}
					if index == 1 && (err != nil || !permission.renewed || permission.permission.Facts().Subject != second) {
						t.Fatal("unrelated browser did not use its own already-prepared renewal", err)
					}
				}
			})
		})
	}
}

func TestBrowserTokensBoundSourcesAndAliasesWithoutEvictingLiveCredentials(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, key, subject := browserTokensFixture(t)
		client := &browserTokenClientFixture{issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			t.Error("install or bound rejection triggered an issuer request")
			return controlv1.VisitorTokenResponse{}, clientcontrol.ErrUnavailable
		}}
		tokens, err := startBrowserTokens(t.Context(), client, policy.lease, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tokens.Close()
		parent := time.Now().Add(30 * time.Minute)
		var original controlv1.VisitorTokenResponse
		for index := range maximumBrowserTokenSources + 1 {
			var secret [32]byte
			secret[0], secret[1] = byte(index), byte(index>>8)
			response := signedBrowserPermission(t, policy, key, subject, time.Now().Add(5*time.Minute))
			err := tokens.install(browserSourceFixture(base64.RawURLEncoding.EncodeToString(secret[:])), response, parent)
			if (err == nil) != (index < maximumBrowserTokenSources) {
				t.Fatal("source bound changed", index, err)
			}
			if index == 0 {
				original = response
			}
		}
		for range maximumBrowserTokenAliases - 1 {
			response := signedBrowserPermission(t, policy, key, subject, time.Now().Add(5*time.Minute))
			if err := tokens.install(browserSourceFixture(liveBrowserCookie), response, parent); err != nil {
				t.Fatal(err)
			}
		}
		response := signedBrowserPermission(t, policy, key, subject, time.Now().Add(5*time.Minute))
		if err := tokens.install(browserSourceFixture(liveBrowserCookie), response, parent); err == nil {
			t.Fatal("alias bound was not enforced")
		}
		_, release, found := tokens.use(visitortoken.Token(original.VisitorToken), nil)
		release()
		if !found || client.calls.Load() != 0 || len(tokens.sources) != maximumBrowserTokenSources {
			t.Fatal("bound rejection evicted live authority or started control work")
		}
	})
}
