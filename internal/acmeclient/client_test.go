package acmeclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientRegistersAccountAndCreatesProfileOrder(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	retryAfter := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	const registration = `{"contact":["mailto:operator@example.test"],"termsOfServiceAgreed":true}`
	server := newScriptedACMEServer(t, key, []acmeStep{
		{method: "GET", path: "/dir", status: 200, body: `{"newNonce":"$ORIGIN/nonce","newAccount":"$ORIGIN/new-account","newOrder":"$ORIGIN/new-order","meta":{"termsOfService":"$ORIGIN/terms","profiles":{"tlsserver":"server"}}}`},
		{method: "HEAD", path: "/nonce", status: 204, nextNonce: "nonce-1"},
		{method: "POST", path: "/new-account", nonce: "nonce-1", payload: registration,
			status: 400, nextNonce: "nonce-2-replacement", body: `{"type":"urn:ietf:params:acme:error:badNonce","detail":"retry"}`},
		{method: "POST", path: "/new-account", nonce: "nonce-2-replacement", payload: registration,
			status: 201, nextNonce: "nonce-3", location: "/account/1", body: `{"status":"valid","contact":["mailto:operator@example.test"]}`},
		{method: "POST", path: "/new-order", nonce: "nonce-3", kid: "/account/1",
			payload: `{"identifiers":[{"type":"dns","value":"route.example.test"}],"profile":"tlsserver"}`,
			status:  201, nextNonce: "nonce-4", location: "/order/1", retryAfter: retryAfter.Format(http.TimeFormat),
			body: `{"status":"pending","identifiers":[{"type":"dns","value":"route.example.test"}],"authorizations":["$ORIGIN/authorization/1"],"finalize":"$ORIGIN/finalize/1"}`},
		{method: "POST", path: "/challenge/1", nonce: "nonce-4", kid: "/account/1", payload: `{}`,
			status: 200, nextNonce: "nonce-5", retryAfter: retryAfter.Format(http.TimeFormat), body: `{"status":"pending"}`},
	})
	httpClient := server.Client()
	httpClient.Timeout = 5 * time.Second
	client, err := New(httpClient, server.URL+"/dir", key, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	account, directory, err := client.ReconcileAccount(ctx, "operator@example.test", true)
	if err != nil {
		t.Fatal(err)
	}
	if account.URL != server.URL+"/account/1" || account.Status != "valid" || directory.Meta.TermsOfService != server.URL+"/terms" {
		t.Fatalf("account = %#v, directory = %#v", account, directory)
	}
	order, err := client.NewOrder(ctx, []string{"route.example.test"}, "tlsserver")
	if err != nil {
		t.Fatal(err)
	}
	if order.URL != server.URL+"/order/1" || order.Status != "pending" ||
		!reflect.DeepEqual(order.Authorizations, []string{server.URL + "/authorization/1"}) ||
		order.Finalize != server.URL+"/finalize/1" || !order.RetryAfter.Equal(retryAfter) {
		t.Fatalf("order = %#v", order)
	}
	challengeRetryAfter, err := client.AcceptChallenge(ctx, server.URL+"/challenge/1")
	if err != nil || !challengeRetryAfter.Equal(retryAfter) {
		t.Fatalf("challenge retry after = %v, %v", challengeRetryAfter, err)
	}
}

func TestAuthorizationDecodesChallengeProblem(t *testing.T) {
	var authorization Authorization
	err := json.Unmarshal([]byte(`{
		"status":"invalid",
		"identifier":{"type":"dns","value":"route.example.test"},
		"challenges":[{
			"type":"tls-alpn-01",
			"url":"https://acme.example.test/challenge/1",
			"status":"invalid",
			"token":"token-1",
			"error":{"type":"urn:ietf:params:acme:error:connection","detail":"connection refused","status":400}
		}]
	}`), &authorization)
	if err != nil {
		t.Fatal(err)
	}
	problem := authorization.Challenges[0].Error
	if problem == nil || problem.Type != "urn:ietf:params:acme:error:connection" ||
		problem.Detail != "connection refused" || problem.Status != 400 {
		t.Fatalf("challenge problem = %#v", problem)
	}
}

// each step supplies a response and records the request for assertions on the
// test goroutine. distinct nonces make stale reuse and extra HEADs observable.
type acmeStep struct {
	method, path, nonce, kid, payload     string
	status                                int
	nextNonce, location, retryAfter, body string
}

func newScriptedACMEServer(t *testing.T, key *ecdsa.PrivateKey, steps []acmeStep) *httptest.Server {
	t.Helper()
	type recordedRequest struct {
		method, path, contentType string
		protected                 map[string]any
		payload                   []byte
		err                       error
	}
	var mu sync.Mutex
	var requests []recordedRequest
	var writeErrors []error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		record := recordedRequest{method: r.Method, path: r.URL.RequestURI(), contentType: r.Header.Get("Content-Type")}
		if r.Method == http.MethodPost {
			record.protected, record.payload, record.err = verifyTestJWS(r, key)
		}
		index := len(requests)
		requests = append(requests, record)
		if index >= len(steps) {
			http.Error(w, "unexpected request", http.StatusInternalServerError)
			return
		}
		step := steps[index]
		origin := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		if step.nextNonce != "" {
			w.Header().Set("Replay-Nonce", step.nextNonce)
		}
		if step.location != "" {
			w.Header().Set("Location", origin+step.location)
		}
		if step.retryAfter != "" {
			w.Header().Set("Retry-After", step.retryAfter)
		}
		w.WriteHeader(step.status)
		if _, err := io.WriteString(w, strings.ReplaceAll(step.body, "$ORIGIN", origin)); err != nil {
			writeErrors = append(writeErrors, err)
		}
	}))
	t.Cleanup(func() {
		server.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, err := range writeErrors {
			t.Errorf("script response: %v", err)
		}
		if len(requests) != len(steps) {
			t.Errorf("requests = %d, want %d", len(requests), len(steps))
		}
		for index, got := range requests {
			if index >= len(steps) {
				break
			}
			want := steps[index]
			if got.method != want.method || got.path != want.path || got.err != nil {
				t.Errorf("request %d: %s %s, JWS error = %v; want %s %s", index, got.method, got.path, got.err, want.method, want.path)
			}
			if want.method != http.MethodPost {
				continue
			}
			protected := map[string]any{"alg": "ES256", "url": server.URL + want.path, "nonce": want.nonce}
			if want.kid != "" {
				protected["kid"] = server.URL + want.kid
			} else {
				protected["jwk"] = map[string]any{"crv": "P-256", "kty": "EC",
					"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
					"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}
			}
			if got.contentType != "application/jose+json" || !reflect.DeepEqual(got.protected, protected) {
				t.Errorf("request %d: content type=%q protected=%#v, want %#v", index, got.contentType, got.protected, protected)
			}
			var payload, expected any
			if err := json.Unmarshal([]byte(want.payload), &expected); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(got.payload, &payload); err != nil || !reflect.DeepEqual(payload, expected) {
				t.Errorf("request %d: payload=%s, want %s; error=%v", index, got.payload, want.payload, err)
			}
		}
	})
	return server
}

func verifyTestJWS(request *http.Request, key *ecdsa.PrivateKey) (map[string]any, []byte, error) {
	var envelope struct{ Protected, Payload, Signature string }
	if err := json.NewDecoder(request.Body).Decode(&envelope); err != nil {
		return nil, nil, err
	}
	protectedJSON, err := base64.RawURLEncoding.DecodeString(envelope.Protected)
	if err != nil {
		return nil, nil, err
	}
	var protected map[string]any
	if err := json.Unmarshal(protectedJSON, &protected); err != nil {
		return nil, nil, err
	}
	if nonce, ok := protected["nonce"].(string); !ok || nonce == "" {
		return protected, nil, fmt.Errorf("missing or invalid nonce: %#v", protected["nonce"])
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != 64 {
		return protected, nil, fmt.Errorf("signature length = %d, error = %v", len(signature), err)
	}
	digest := sha256.Sum256([]byte(envelope.Protected + "." + envelope.Payload))
	if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return protected, nil, fmt.Errorf("invalid JWS signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	return protected, payload, err
}
