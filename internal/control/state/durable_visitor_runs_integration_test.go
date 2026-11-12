package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationDurableVisitorBearerSurvivesNewPublisherRun(t *testing.T) {
	for _, kind := range []string{"share", "service"} {
		t.Run(kind, func(t *testing.T) {
			d, now, _, _ := newPublishRunPrerequisites(t)
			r := oidcRouteRequest(t, d, now)
			scope := visitorscope.Scope{Kind: visitorscope.PublicURL}
			var token visitortoken.Token
			var start func(time.Time, string) (controlv1.VisitorPolicyUpdate, func())
			if kind == "share" {
				url := createTestPublicURL(t, d, r, now)
				scope.ID = url.ID
				secret := bytes.Repeat([]byte{7}, 32)
				share, err := d.CreateShare(t.Context(), CreateShareRequest{TeamID: url.TeamID, ActingIdentityID: r.ActingIdentityID, IdempotencyKey: "durable", SecretFingerprint: sha256.Sum256(secret), ExpiresAt: now.Add(7 * 24 * time.Hour), PolicyRevision: 1, PublicURLs: []AuthorizedSharePublicURL{{PublicURLID: url.ID, ExpectedMutationRevision: url.MutationRevision}}}, now)
				if err != nil {
					t.Fatal(err)
				}
				token, err = visitortoken.ShareToken(share.ID, secret)
				if err != nil {
					t.Fatal(err)
				}
				start = func(at time.Time, key string) (controlv1.VisitorPolicyUpdate, func()) {
					t.Helper()
					request := PublishRunRequest{PublicURLID: url.ID, TeamID: url.TeamID, MembershipID: r.MembershipID, ActingIdentityID: r.ActingIdentityID, RetrySecret: secret, IdempotencyKey: key, RequestDigest: sha256.Sum256([]byte(key)), PolicyRevision: uint64(url.PolicyRevision), CertificateCacheKey: url.ID, CertificateScope: "public-url", CertificateIdentifiers: []string{url.CanonicalHostname}, CertificateChallenge: "dns-01"}
					if err := d.pool.QueryRow(t.Context(), `SELECT mutation_revision FROM control.public_urls WHERE id=$1`, url.ID).Scan(&request.ExpectedMutationRevision); err != nil {
						t.Fatal(err)
					}
					run, err := d.CreatePublishRun(t.Context(), request, at, time.Minute, time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					body, err := d.ReadPublisherVisitorPolicy(t.Context(), scope, run.PublishRunID, int64(run.PublishRunNumber), run.PublishRunToken.String(), 0, at)
					if err != nil {
						t.Fatal(err)
					}
					return body, func() {
						if err := d.ClosePublishRun(t.Context(), run.PublishRunID, run.PublishRunToken, at.Add(time.Second)); err != nil {
							t.Fatal(err)
						}
					}
				}
			} else {
				service, err := d.CreateServiceAt(t.Context(), r.TeamID, r.ActingIdentityID, "durable", "durable", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"})
				if err != nil {
					t.Fatal(err)
				}
				scope.Kind, scope.ID = visitorscope.Service, service.ID
				credential, err := d.CreateServiceHTTPGrant(t.Context(), service.ID, r.ActingIdentityID, controlv1.CreateVisitorCredentialRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service.ID}, Kind: "token", ExpiresAt: now.Add(7 * 24 * time.Hour)}, now)
				if err != nil {
					t.Fatal(err)
				}
				token = visitortoken.Token(credential.Permission.VisitorToken)
				enrollment := publisherEnrollment(t, d, r, PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: service.ID}, now)
				key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
				publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, key.Public().(ed25519.PublicKey), now)
				if err != nil {
					t.Fatal(err)
				}
				start = func(at time.Time, key string) (controlv1.VisitorPolicyUpdate, func()) {
					t.Helper()
					prepared, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, key, at, ServiceMetadata{Protocol: "http", TrustRevision: service.TrustRevision}, nil)
					if err != nil {
						t.Fatal(err)
					}
					run, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, at)
					if err != nil {
						t.Fatal(err)
					}
					body, err := d.ReadPublisherVisitorPolicy(t.Context(), scope, run.RunID, run.RunNumber, run.Token, 0, at)
					if err != nil {
						t.Fatal(err)
					}
					return body, func() {
						if err := d.CloseServiceRun(t.Context(), service.ID, run.RunID, run.Token, at.Add(time.Second)); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			for i, elapsed := range []time.Duration{0, 6 * 24 * time.Hour} {
				at := now.Add(elapsed)
				if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, at); err != nil {
					t.Fatal(err)
				}
				// placement belongs to the new run, not to its visitor credential.
				if i > 0 {
					for slot := range publishRunConnectionCount {
						registration := relayLifecycleRegistration(fmt.Sprintf("placement-%d", slot))
						registration.ConnectionCapacity = 10
						if _, err := d.RegisterRelay(t.Context(), registration, at, time.Hour); err != nil {
							t.Fatal(err)
						}
					}
				}
				body, stop := start(at, fmt.Sprintf("run-%d", i))
				update, err := visitorlease.Decode(body)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := visitortoken.VerifyBearer(token, update.View, at); err != nil {
					t.Fatal("new run rejected original advertised bearer", err)
				}
				stop()
			}
		})
	}
}
