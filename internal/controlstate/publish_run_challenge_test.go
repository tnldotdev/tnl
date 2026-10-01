package controlstate

import (
	"bytes"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
)

func TestPublishRunRequestValidatesChallengeMethod(t *testing.T) {
	request := PublishRunRequest{
		PublicURLID: "public_url_1", TeamID: "team_1", ActingIdentityID: "identity_1",
		IdempotencyKey: "run", PolicyRevision: 1, ExpectedMutationRevision: 1,
		RetrySecret: bytes.Repeat([]byte{1}, 32), CertificateCacheKey: "route.example.test",
		CertificateScope: "route.example.test", CertificateIdentifiers: []string{"route.example.test"},
	}
	for _, test := range []struct {
		name        string
		method      certificateidentity.ChallengeMethod
		identifiers []string
		wantError   bool
	}{
		{"tls_alpn", certificateidentity.ChallengeTLSALPN01, []string{"route.example.test"}, false},
		{"dns_wildcard", certificateidentity.ChallengeDNS01, []string{"*.route.example.test", "route.example.test"}, false},
		{"unknown", certificateidentity.ChallengeMethod("other"), []string{"route.example.test"}, true},
		{"tls_wildcard", certificateidentity.ChallengeTLSALPN01, []string{"*.route.example.test", "route.example.test"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request.CertificateChallenge = test.method
			request.CertificateIdentifiers = test.identifiers
			if err := validatePublishRunRequest(request, time.Minute, time.Minute); (err != nil) != test.wantError {
				t.Fatalf("challenge method %q with identifiers %q: %v", test.method, test.identifiers, err)
			}
		})
	}
}
