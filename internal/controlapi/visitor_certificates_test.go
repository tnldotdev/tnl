package controlapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/visitorcert"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type visitorCertificateStoreStub struct {
	allowed, checked  bool
	urlID, identityID string
}

func (s *visitorCertificateStoreStub) DatabaseVisitorAllowed(_ context.Context, urlID, identityID string, _ time.Time) (bool, error) {
	s.checked, s.urlID, s.identityID = true, urlID, identityID
	return s.allowed, nil
}

func TestVisitorCertificateRequiresCurrentIdentityAndDatabaseURLGrant(t *testing.T) {
	issuer, err := visitorcert.New(bytes.Repeat([]byte{0x3a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const urlID = "url_0123456789abcdefghijkl"
	const identityID = "ident_0123456789abcdefghijkl"
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(controlv1.CreateVisitorCertificateRequest{PublicUrlId: urlID, Csr: csr})
	if err != nil {
		t.Fatal(err)
	}
	store := &visitorCertificateStoreStub{}
	h := &handler{config: Config{VisitorIssuer: issuer}, visitorCertificates: store,
		authorizer: &recordingAuthorizer{principal: publicURLReadPrincipal{identityID: identityID}}}
	request := func(token bool, payload []byte) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/v1/visitor-certificates", bytes.NewReader(payload))
		if token {
			r.Header.Set("Authorization", "Bearer access-token")
		}
		response := httptest.NewRecorder()
		h.CreateVisitorCertificate(response, r)
		return response
	}
	if response := request(false, body); response.Code != http.StatusUnauthorized || store.checked {
		t.Fatalf("unsigned certificate request = %d, checked=%t", response.Code, store.checked)
	}
	if response := request(true, body); response.Code != http.StatusForbidden || !store.checked || store.urlID != urlID || store.identityID != identityID {
		t.Fatalf("ungranted certificate request = %d, checked=%t, url=%s, identity=%s", response.Code, store.checked, store.urlID, store.identityID)
	}
	store.allowed = true
	if response := request(true, []byte(`{"public_url_id":"`+urlID+`","csr":""}`)); response.Code != http.StatusBadRequest {
		t.Fatalf("empty certificate request = %d", response.Code)
	}
	response := request(true, body)
	if response.Code != http.StatusCreated || strings.Contains(response.Body.String(), "PRIVATE KEY") {
		t.Fatalf("visitor certificate response = %d %s", response.Code, response.Body.String())
	}
	var result controlv1.VisitorCertificate
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(result.CertificatePem))
	if block == nil || result.IssuerPem != string(issuer.CertificatePEM()) {
		t.Fatal("issuer returned a malformed visitor certificate chain")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if identity, err := issuer.Identity(leaf, urlID, time.Now()); err != nil || identity != identityID || !result.NotAfter.Equal(leaf.NotAfter) ||
		result.NotAfter.After(time.Now().Add(visitorcert.MaxLifetime)) {
		t.Fatalf("issued certificate identity = %s, expiry = %s, %v", identity, result.NotAfter, err)
	}
}

func TestDatabaseVisitorCertificateRechecksCurrentGrantForExactRun(t *testing.T) {
	issuer, err := visitorcert.New(bytes.Repeat([]byte{0x4b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const urlID = "url_0123456789abcdefghijkl"
	const identityID = "ident_0123456789abcdefghijkl"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(csr, urlID, identityID, time.Now().Add(time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issued)
	if block == nil {
		t.Fatal("missing visitor certificate")
	}
	store := &visitorCertificateStoreStub{allowed: true}
	publication := &browserRunAuthStoreStub{auth: controlstate.PublishRunAuthentication{
		PublicURLID: urlID, PublishRunID: "pr_current", PublishRunNumber: 7, PublishRunToken: credentials.PublishRunToken("current-token"),
	}}
	h := &handler{config: Config{VisitorIssuer: issuer}, visitorCertificates: store, store: publication}
	check := func(cert []byte, want int) {
		t.Helper()
		body, err := json.Marshal(controlv1.DatabaseVisitorCertificateRequest{Certificate: cert, PublishRunNumber: 7})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/publish-runs/pr_current/visitor-certificate/access", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer current-token")
		response := httptest.NewRecorder()
		h.CheckDatabaseVisitorCertificate(response, request, "pr_current")
		if response.Code != want {
			t.Fatalf("visitor certificate access = %d %s; want %d", response.Code, response.Body.String(), want)
		}
	}
	check(block.Bytes, http.StatusNoContent)
	if !store.checked || store.urlID != urlID || store.identityID != identityID || publication.number != 7 {
		t.Fatalf("visitor access did not check the exact publish run and identity: %+v, %+v", store, publication)
	}
	store.allowed = false
	check(block.Bytes, http.StatusForbidden)
	store.allowed = true
	publication.auth.PublicURLID = "url_abcdefghijkl0123456789"
	check(block.Bytes, http.StatusForbidden)
	publication.auth.PublicURLID = urlID
	block.Bytes[len(block.Bytes)-1] ^= 1
	check(block.Bytes, http.StatusForbidden)
	publication.err = controlstate.ErrPublishRunCredential
	check(block.Bytes, http.StatusUnauthorized)
}
