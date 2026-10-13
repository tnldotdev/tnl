package clientauth

import (
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestPublisherClientsDoNotForwardHumanControlSession(t *testing.T) {
	humanToken := issuedSession(t).AccessToken
	transport := &recordingTransport{}
	transport.respond = func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/publisher/public-url":
			if request.Header.Get("Authorization") != "Bearer pta_publisher" {
				t.Errorf("publisher access header = %q", request.Header.Get("Authorization"))
			}
			return jsonResponse(http.StatusOK, map[string]any{"id": "url_selected", "team_id": "tm_selected"}), nil
		case "/v1/public-urls/url_selected":
			if request.Header.Get("Authorization") != "Bearer "+humanToken {
				t.Errorf("human access header = %q", request.Header.Get("Authorization"))
			}
			return jsonResponse(http.StatusOK, map[string]any{"id": "url_selected", "team_id": "tm_selected"}), nil
		case "/v1/publisher/enrollments/redeem":
			if request.Header.Get("Authorization") != "" {
				t.Errorf("enrollment forwarded a human token: %q", request.Header.Get("Authorization"))
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"client_id": "pub_0123456789abcdefghijkl", "key_id": "pik_0123456789abcdefghijkl",
				"grant_id": "pgr_0123456789abcdefghijkl", "team_id": "tm_selected",
				"public_url_id": "url_selected", "kind": "saved_url",
			}), nil
		default:
			t.Errorf("unexpected request %s", request.URL.Path)
			return jsonResponse(http.StatusNotFound, map[string]any{"code": "not_found"}), nil
		}
	}
	resolved := control{serverEndpoint: testControlOrigin, rawHTTP: &http.Client{Transport: transport}, discovery: controlv1.ControlDiscovery{}}
	authenticated, err := authenticatedResult(resolved, &tokenSource{control: resolved, explicit: humanToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticated.Control.GetPublicURL(t.Context(), "url_selected"); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticated.PublisherControl.PublisherPublicURL(t.Context(), "pta_publisher"); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticated.PublisherAuthority.RedeemPublisherEnrollment(t.Context(), "secret-enrollment-key", make(ed25519.PublicKey, ed25519.PublicKeySize)); err != nil {
		t.Fatal(err)
	}
	for _, recorded := range transport.snapshot() {
		if strings.HasPrefix(recorded.url, testControlOrigin+"/v1/publisher/") &&
			strings.Contains(recorded.header.Get("Authorization"), humanToken) {
			t.Fatalf("human token reached publisher endpoint %s", recorded.url)
		}
	}
}
