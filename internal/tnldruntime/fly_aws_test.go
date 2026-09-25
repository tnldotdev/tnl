package tnldruntime

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFlyIdentityTokenRetriever(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tokens/oidc" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected token request: %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != `{"aud":"sts.amazonaws.com"}` {
			t.Errorf("unexpected OIDC audience: %s (%v)", body, err)
		}
		_, _ = io.WriteString(w, "fresh.jwt.token\n")
	}))
	defer server.Close()

	retriever := flyTokenRetriever{client: server.Client()}
	// The real client uses a Fly Unix socket; replace only its URL for this test.
	client := retriever.client
	client.Transport = rewriteFlyTransport{base: server.Client().Transport, target: server.URL}
	for range 2 {
		token, err := retriever.GetIdentityToken()
		if err != nil || string(token) != "fresh.jwt.token" {
			t.Fatalf("retrieve fresh OIDC token: %q, %v", token, err)
		}
	}
}

type rewriteFlyTransport struct {
	base   http.RoundTripper
	target string
}

func (t rewriteFlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.URL.Host = strings.TrimPrefix(t.target, "http://")
	return t.base.RoundTrip(copy)
}

func TestFlyIdentityTokenRetrieverDoesNotRevealFailedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "private response")
	}))
	defer server.Close()
	retriever := flyTokenRetriever{client: &http.Client{Transport: rewriteFlyTransport{base: server.Client().Transport, target: server.URL}}}
	_, err := retriever.GetIdentityToken()
	if err == nil || !strings.Contains(err.Error(), "status 403") || strings.Contains(err.Error(), "private response") {
		t.Fatalf("expected status without response body, got %v", err)
	}
}
