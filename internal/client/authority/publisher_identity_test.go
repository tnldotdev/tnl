package authority

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestRedeemPublisherEnrollmentPreservesKeyWithoutManagementAuthority(t *testing.T) {
	const secret = "pen_0123456789abcdefghijkl." + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	want := authorityv1.PublisherEnrollmentResult{
		ClientId: "pub_0123456789abcdefghijkl", KeyId: "pkey_0123456789abcdefghijkl",
		GrantId: "pgrant_0123456789abcdefghijkl", TeamId: "tm_0123456789abcdefghijkl",
		Kind: authorityv1.Service, ServiceId: new("svc_0123456789abcdefghijkl"),
	}
	response, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		access credentials.AccessToken
	}{
		{"without session", ""},
		{"with management session", "management-access"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client, err := New("https://authority.example", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				defer r.Body.Close()
				if r.Method != http.MethodPost || r.URL.String() != "https://authority.example/v1/publisher-enrollments/redeem" {
					t.Error("redemption changed its authority endpoint")
				}
				if len(r.Header.Values("Authorization")) != 0 {
					t.Error("redemption included management authorization")
				}
				var body authorityv1.RedeemPublisherEnrollmentRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					return nil, err
				}
				if body.EnrollmentKey != secret {
					t.Error("redemption changed its enrollment key")
				}
				if body.PublicKey != base64.RawURLEncoding.EncodeToString(public) {
					t.Error("redemption changed its signing public key")
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(response))}, nil
			})}, test.access)
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.RedeemPublisherEnrollment(t.Context(), secret, public)
			if err != nil || calls != 1 || !reflect.DeepEqual(got, want) {
				t.Fatalf("redemption calls=%d error=%v", calls, err)
			}
		})
	}
}
