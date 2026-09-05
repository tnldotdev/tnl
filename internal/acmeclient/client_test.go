package acmeclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientRegistersAccountAndCreatesProfileOrder(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	nonceCounter := 0
	accountAttempts := 0
	retryAfter := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		endpoint := server.URL + request.URL.Path
		switch request.URL.Path {
		case "/dir":
			writeTestJSON(t, response, map[string]any{
				"newNonce": server.URL + "/nonce", "newAccount": server.URL + "/new-account",
				"newOrder": server.URL + "/new-order",
				"meta":     map[string]any{"termsOfService": server.URL + "/terms", "profiles": map[string]string{"tlsserver": "server"}},
			})
		case "/nonce":
			nonceCounter++
			response.Header().Set("Replay-Nonce", "nonce-head")
			response.WriteHeader(http.StatusNoContent)
		case "/new-account":
			accountAttempts++
			protected, payload := verifyTestJWS(t, request, key, endpoint)
			if protected["kid"] != nil || protected["jwk"] == nil {
				t.Fatalf("account protected header = %#v", protected)
			}
			var registration struct {
				Contact              []string `json:"contact"`
				TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
			}
			if err := json.Unmarshal(payload, &registration); err != nil {
				t.Fatal(err)
			}
			if len(registration.Contact) != 1 || registration.Contact[0] != "mailto:operator@example.test" || !registration.TermsOfServiceAgreed {
				t.Fatalf("account registration = %#v", registration)
			}
			response.Header().Set("Replay-Nonce", "nonce-account")
			if accountAttempts == 1 {
				response.WriteHeader(http.StatusBadRequest)
				writeTestJSON(t, response, map[string]any{
					"type": "urn:ietf:params:acme:error:badNonce", "detail": "retry",
				})
				return
			}
			response.Header().Set("Location", server.URL+"/account/1")
			response.WriteHeader(http.StatusCreated)
			writeTestJSON(t, response, map[string]any{"status": "valid", "contact": registration.Contact})
		case "/new-order":
			protected, payload := verifyTestJWS(t, request, key, endpoint)
			if protected["kid"] != server.URL+"/account/1" || protected["jwk"] != nil {
				t.Fatalf("order protected header = %#v", protected)
			}
			var orderRequest struct {
				Identifiers []Identifier `json:"identifiers"`
				Profile     string       `json:"profile"`
			}
			if err := json.Unmarshal(payload, &orderRequest); err != nil {
				t.Fatal(err)
			}
			if len(orderRequest.Identifiers) != 1 || orderRequest.Identifiers[0] != (Identifier{Type: "dns", Value: "route.example.test"}) || orderRequest.Profile != "tlsserver" {
				t.Fatalf("order request = %#v", orderRequest)
			}
			response.Header().Set("Replay-Nonce", "nonce-order")
			response.Header().Set("Location", server.URL+"/order/1")
			response.Header().Set("Retry-After", retryAfter.Format(http.TimeFormat))
			response.WriteHeader(http.StatusCreated)
			writeTestJSON(t, response, map[string]any{
				"status": "pending", "identifiers": orderRequest.Identifiers,
				"authorizations": []string{server.URL + "/authorization/1"}, "finalize": server.URL + "/finalize/1",
			})
		case "/challenge/1":
			verifyTestJWS(t, request, key, endpoint)
			response.Header().Set("Replay-Nonce", "nonce-challenge")
			response.Header().Set("Retry-After", retryAfter.Format(http.TimeFormat))
			writeTestJSON(t, response, map[string]any{"status": "pending"})
		default:
			http.NotFound(response, request)
		}
	})
	server = httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(server.Client(), server.URL+"/dir", key, "")
	if err != nil {
		t.Fatal(err)
	}
	account, directory, err := client.ReconcileAccount(t.Context(), "operator@example.test", true)
	if err != nil {
		t.Fatal(err)
	}
	if account.URL != server.URL+"/account/1" || account.Status != "valid" || directory.Meta.TermsOfService != server.URL+"/terms" || accountAttempts != 2 || nonceCounter != 1 {
		t.Fatalf("account = %#v, directory = %#v, attempts = %d, nonces = %d", account, directory, accountAttempts, nonceCounter)
	}
	order, err := client.NewOrder(t.Context(), []string{"route.example.test"}, "tlsserver")
	if err != nil {
		t.Fatal(err)
	}
	if order.URL != server.URL+"/order/1" || order.Status != "pending" || len(order.Authorizations) != 1 ||
		!order.RetryAfter.Equal(retryAfter) {
		t.Fatalf("order = %#v", order)
	}
	challengeRetryAfter, err := client.AcceptChallenge(t.Context(), server.URL+"/challenge/1")
	if err != nil || !challengeRetryAfter.Equal(retryAfter) {
		t.Fatalf("challenge retry after = %v, %v", challengeRetryAfter, err)
	}
}

func verifyTestJWS(t *testing.T, request *http.Request, key *ecdsa.PrivateKey, endpoint string) (map[string]any, []byte) {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	protectedJSON, err := base64.RawURLEncoding.DecodeString(envelope.Protected)
	if err != nil {
		t.Fatal(err)
	}
	var protected map[string]any
	if err := json.Unmarshal(protectedJSON, &protected); err != nil {
		t.Fatal(err)
	}
	if protected["alg"] != "ES256" || protected["url"] != endpoint || protected["nonce"] == "" {
		t.Fatalf("protected header = %#v", protected)
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != 64 {
		t.Fatalf("signature length = %d, error = %v", len(signature), err)
	}
	digest := sha256.Sum256([]byte(envelope.Protected + "." + envelope.Payload))
	if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("JWS signature is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return protected, payload
}

func writeTestJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Fatal(err)
	}
}
