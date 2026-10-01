package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
)

// this stub shares ACME behavior only. public URL and relay rules stay in their tests.
type acmeStub struct {
	order, finalizedOrder acmeclient.Order
	authorization         acmeclient.Authorization
	authorizations        map[string]acmeclient.Authorization
	getOrder              func(string) (acmeclient.Order, error)
	getAuthorization      func(string) (acmeclient.Authorization, error)
	certificatePEM        []byte
	challengeRetryAt      time.Time

	newOrderErr         error
	getOrderErr         error
	getAuthorizationErr error
	acceptErr           error
	finalizeErr         error
	downloadErr         error
	keyAuthorizationErr error

	newOrderCalls, acceptCalls int
	newOrders                  []newOrderCall
	orderURLs                  []string
	authorizationURLs          []string
	challengeURLs              []string
	certificateURLs            []string
	tokens                     []string
	finalizations              []finalizeCall
	acceptedChallenge          string
	finalizedCSR               []byte
}

type newOrderCall struct {
	identifiers []string
	profile     string
}
type finalizeCall struct {
	orderURL, finalizeURL string
	csr                   []byte
}

func (s *acmeStub) NewOrder(_ context.Context, identifiers []string, profile string) (acmeclient.Order, error) {
	s.newOrderCalls++
	s.newOrders = append(s.newOrders, newOrderCall{append([]string(nil), identifiers...), profile})
	return s.order, s.newOrderErr
}

func (s *acmeStub) GetOrder(_ context.Context, url string) (acmeclient.Order, error) {
	s.orderURLs = append(s.orderURLs, url)
	if s.getOrder != nil {
		return s.getOrder(url)
	}
	return s.order, s.getOrderErr
}

func (s *acmeStub) GetAuthorization(_ context.Context, url string) (acmeclient.Authorization, error) {
	s.authorizationURLs = append(s.authorizationURLs, url)
	if s.getAuthorization != nil {
		return s.getAuthorization(url)
	}
	if s.authorizations != nil {
		return s.authorizations[url], s.getAuthorizationErr
	}
	return s.authorization, s.getAuthorizationErr
}

func (s *acmeStub) AcceptChallenge(_ context.Context, url string) (time.Time, error) {
	s.acceptedChallenge = url
	s.acceptCalls++
	s.challengeURLs = append(s.challengeURLs, url)
	return s.challengeRetryAt, s.acceptErr
}

func (s *acmeStub) FinalizeOrder(_ context.Context, orderURL, finalizeURL string, csr []byte) (acmeclient.Order, error) {
	s.finalizedCSR = append([]byte(nil), csr...)
	s.finalizations = append(s.finalizations, finalizeCall{orderURL, finalizeURL, append([]byte(nil), csr...)})
	return s.finalizedOrder, s.finalizeErr
}

func (s *acmeStub) DownloadCertificate(_ context.Context, url string) ([]byte, error) {
	s.certificateURLs = append(s.certificateURLs, url)
	return append([]byte(nil), s.certificatePEM...), s.downloadErr
}

func (s *acmeStub) KeyAuthorization(token string) (string, error) {
	s.tokens = append(s.tokens, token)
	return token + ".thumbprint", s.keyAuthorizationErr
}

func testCertificate(t *testing.T, hostname string, now time.Time) ([]byte, []byte) {
	t.Helper()
	return testCertificateValidity(t, hostname, now.Add(-time.Minute), now.Add(time.Hour))
}

func testCertificateValidity(t *testing.T, hostname string, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{hostname}}, key)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return csrDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
}
