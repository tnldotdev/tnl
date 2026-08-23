package controltls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestChallengeServingReadsCurrentSharedCertificate(t *testing.T) {
	cache := newMemoryCache()
	first, second := refreshTestSource(t, cache), refreshTestSource(t, cache)
	hello := &tls.ClientHelloInfo{ServerName: "CONTROL.EXAMPLE", SupportedProtos: []string{acme.ALPNProto}}
	var previous []byte
	for _, token := range []string{"first-token", "replacement-token"} {
		certificate, err := first.client.TLSALPN01ChallengeCert(token, "control.example")
		if err != nil {
			t.Fatal(err)
		}
		data, err := certificatePEM(&certificate)
		if err != nil {
			t.Fatal(err)
		}
		if err := cache.Put(t.Context(), "control.example+token", data); err != nil {
			t.Fatal(err)
		}
		for _, source := range []*Source{first, second} {
			got, err := source.GetCertificate(hello)
			if err != nil || !bytes.Equal(got.Certificate[0], certificate.Certificate[0]) || bytes.Equal(got.Certificate[0], previous) {
				t.Fatalf("source did not serve the current shared challenge: %v", err)
			}
		}
		previous = certificate.Certificate[0]
	}
	if err := cache.Delete(t.Context(), "control.example+token"); err != nil {
		t.Fatal(err)
	}
	for _, source := range []*Source{first, second} {
		if _, err := source.GetCertificate(hello); err == nil {
			t.Error("source served a deleted challenge")
		}
	}
}

func TestCanceledAuthorizationDoesNotDeleteReplacementChallenge(t *testing.T) {
	cache := newMemoryCache()
	source := refreshTestSource(t, cache)
	started := make(chan struct{})
	source.client.KID = "https://acme.example/account"
	source.client.HTTPClient = &http.Client{Transport: lifecycleRoundTripper(func(request *http.Request) (*http.Response, error) {
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}
		response.Header.Set("Replay-Nonce", "bm9uY2U")
		switch request.URL.Path {
		case "/directory":
			body, _ := json.Marshal(map[string]string{
				"newNonce": "https://acme.example/nonce", "newAccount": "https://acme.example/account", "newOrder": "https://acme.example/order",
			})
			response.Body = io.NopCloser(bytes.NewReader(body))
		case "/nonce":
		case "/challenge":
			close(started)
			<-request.Context().Done()
			return nil, request.Context().Err()
		default:
			return nil, errors.New("unexpected ACME request: " + request.URL.Path)
		}
		return response, nil
	})}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- source.authorize(ctx, "control.example", "https://acme.example/authz", &acme.Authorization{
			Challenges: []*acme.Challenge{{Type: "tls-alpn-01", Token: "original", URI: "https://acme.example/challenge"}},
		})
	}()
	t.Cleanup(func() { cancel() })
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("authorization never accepted its challenge: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("authorization never accepted its challenge")
	}
	cancel()
	// memoryCache deliberately ignores cancellation, so this checks that the
	// old owner does not invoke detached cleanup even with such a cache.
	if err := cache.Put(t.Context(), "control.example+token", []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("authorization cancellation: %v", err)
	}
	data, err := cache.Get(t.Context(), "control.example+token")
	if err != nil || string(data) != "replacement" {
		t.Fatalf("old authorization removed the replacement challenge: %q, %v", data, err)
	}
}
