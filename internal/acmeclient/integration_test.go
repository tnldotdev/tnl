package acmeclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestIntegrationPebbleCertificateOrder(t *testing.T) {
	directoryURL := os.Getenv("TNL_TEST_ACME_DIRECTORY_URL")
	caFile := os.Getenv("TNL_TEST_ACME_CA_FILE")
	if directoryURL == "" || caFile == "" {
		t.Skip("TNL_TEST_ACME_DIRECTORY_URL and TNL_TEST_ACME_CA_FILE are not set")
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("ACME CA file contains no certificates")
	}
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}},
		Timeout:   10 * time.Second,
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(httpClient, directoryURL, key, "")
	if err != nil {
		t.Fatal(err)
	}
	account, _, err := client.ReconcileAccount(t.Context(), "integration@example.test", true)
	if err != nil {
		t.Fatal(err)
	}
	if account.Status != "valid" || account.URL == "" {
		t.Fatalf("account = %#v", account)
	}
	randomName := make([]byte, 6)
	if _, err := rand.Read(randomName); err != nil {
		t.Fatal(err)
	}
	hostname := "route-" + hex.EncodeToString(randomName) + ".example.test"
	order, err := client.NewOrder(t.Context(), []string{hostname}, "tlsserver")
	if err != nil {
		t.Fatal(err)
	}
	for _, authorizationURL := range order.Authorizations {
		authorization, err := client.GetAuthorization(t.Context(), authorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		var challengeURL string
		for _, challenge := range authorization.Challenges {
			if challenge.Type == "tls-alpn-01" {
				challengeURL = challenge.URL
				break
			}
		}
		if challengeURL == "" {
			t.Fatal("authorization contains no TLS-ALPN-01 challenge")
		}
		if _, err := client.AcceptChallenge(t.Context(), challengeURL); err != nil {
			t.Fatal(err)
		}
		waitForAuthorization(t, client, authorizationURL)
	}
	order = waitForOrder(t, client, order.URL, "ready")
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{hostname}}, certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	order, err = client.FinalizeOrder(t.Context(), order.URL, order.Finalize, csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if order.Status != "valid" {
		order = waitForOrder(t, client, order.URL, "valid")
	}
	certificatePEM, err := client.DownloadCertificate(t.Context(), order.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("certificate response contains no certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.VerifyHostname(hostname); err != nil {
		t.Fatal(err)
	}
}

func waitForAuthorization(t *testing.T, client *Client, authorizationURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		switch authorization.Status {
		case "valid":
			return
		case "pending", "processing":
		case "invalid", "deactivated", "expired", "revoked":
			t.Fatalf("authorization status = %q", authorization.Status)
		default:
			t.Fatalf("unknown authorization status = %q", authorization.Status)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func waitForOrder(t *testing.T, client *Client, orderURL, expectedStatus string) Order {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		order, err := client.GetOrder(ctx, orderURL)
		if err != nil {
			t.Fatal(err)
		}
		if order.Status == expectedStatus {
			return order
		}
		if order.Status == "invalid" {
			t.Fatal("order became invalid")
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
