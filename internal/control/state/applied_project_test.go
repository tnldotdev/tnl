package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
)

func TestNormalizeProjectConfiguration(t *testing.T) {
	input := ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {Target: "http://localhost:3000"}}}
	c, hash, err := NormalizeProjectConfiguration(input)
	if err != nil || c.Services["web"].Protocol != "http" || c.Services["web"].PublisherGroup != "local" || c.Services["web"].PublicURL != nil {
		t.Fatalf("private HTTP default: %#v %v", c, err)
	}
	_, hash2, err := NormalizeProjectConfiguration(ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{}, Services: map[string]ProjectServiceConfiguration{"web": {Target: "http://localhost:3000", PublisherGroup: "local", Name: "web", Protocol: "http"}}})
	if err != nil || hash2 != hash {
		t.Fatal("defaults do not normalize to the same hash", err)
	}
	if input.Services["web"].Protocol != "" {
		t.Fatal("normalization mutated caller state")
	}
	for name, c := range map[string]ProjectConfiguration{
		"reserved local":      {PublisherGroups: map[string]ProjectPublisherGroup{"local": {}}},
		"unknown group":       {Services: map[string]ProjectServiceConfiguration{"db": {PublisherGroup: "missing", Target: "localhost:5432", Protocol: "postgres"}}},
		"public tcp":          {Services: map[string]ProjectServiceConfiguration{"db": {Target: "localhost:5432", Protocol: "postgres", PublicURL: &ProjectServicePublicURL{}}}},
		"target userinfo":     {Services: map[string]ProjectServiceConfiguration{"web": {Target: "http://user:secret@localhost:3000"}}},
		"invalid port target": {Services: map[string]ProjectServiceConfiguration{"db": {Target: "missing-port", Protocol: "tcp"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := NormalizeProjectConfiguration(c); !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal(err)
			}
		})
	}
}

func TestNormalizeAppliedPublicOriginsMatchRuntime(t *testing.T) {
	for _, target := range []string{"http://localhost:3000", "https://EXAMPLE.test:443", "3000", "http://example.test", "https://example.test", "http://example.test:80/", "http://example.test:80#", "http://example.test:80?", "http://[2001:db8::1]:80", "http://user:secret@example.test:80", "http://example.test:0"} {
		t.Run(target, func(t *testing.T) {
			want, runtimeErr := targetsyntax.NormalizeTarget(target)
			c, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {Target: target, PublicURL: &ProjectServicePublicURL{}}}})
			if (runtimeErr != nil) != (err != nil) || err == nil && c.Services["web"].Target != want {
				t.Fatal("apply and runtime disagree about public origin", c, err, runtimeErr)
			}
		})
	}
}

func TestNormalizeAppliedHTTPSettingsDoNotDisappear(t *testing.T) {
	settings := &config.HTTPService{Readiness: &config.Readiness{Path: "/health"}, Paths: map[string]config.PathMount{"/api": {Service: "api", StripPrefix: true}}}
	c, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {Target: "app", PublicURL: &ProjectServicePublicURL{}, HTTP: settings}, "api": {Target: "http://localhost:3001"}}})
	if err != nil || c.Services["web"].HTTP.Readiness.Path != "/health" || !c.Services["web"].HTTP.Paths["/api"].StripPrefix {
		t.Fatal("local HTTP settings lost", err)
	}
	for _, s := range []*config.HTTPService{{Readiness: &config.Readiness{Path: "/health"}}, {Paths: map[string]config.PathMount{"/api": {Service: "api"}}}, {Open: new(bool)}} {
		_, _, err := NormalizeProjectConfiguration(ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"web": {PublisherGroup: "production", Target: "http://app.internal:3000", HTTP: s}}})
		if !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("unsupported remote HTTP behavior accepted", err)
		}
	}
}

func appliedTargetTrust(t *testing.T, hostname string) *ProjectTargetTLS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	value := &ProjectTargetTLS{Hostname: hostname, CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00" + value.Hostname + "\x00" + value.CAPEM))
	value.Digest = hex.EncodeToString(digest[:])
	return value
}

func TestNormalizeAppliedProjectTargetsAndTrustBoundaries(t *testing.T) {
	trust := appliedTargetTrust(t, "upstream.internal")
	keyTrust := *trust
	keyTrust.CAPEM = "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----"
	keyDigest := sha256.Sum256([]byte("tnl-target-tls/v1\x00" + keyTrust.Hostname + "\x00" + keyTrust.CAPEM))
	keyTrust.Digest = hex.EncodeToString(keyDigest[:])
	for name, s := range map[string]ProjectServiceConfiguration{
		"local app":                  {Target: "app"},
		"local compose":              {Target: "compose:postgres:5432", Protocol: "postgres"},
		"local docker":               {Target: "docker:redis_1:6379", Protocol: "tcp"},
		"local deferred public":      {Target: "app", PublicURL: &ProjectServicePublicURL{Ephemeral: true}},
		"public target trust":        {Target: "https://upstream.internal:8443", PublicURL: &ProjectServicePublicURL{}, TargetTLS: trust},
		"remote literal docker host": {PublisherGroup: "production", Target: "docker:5432", Protocol: "postgres"},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, err := NormalizeProjectConfiguration(ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"service": s}})
			if err != nil || c.Services["service"].Target != s.Target {
				t.Fatalf("target changed or rejected: %v", err)
			}
		})
	}
	for name, s := range map[string]ProjectServiceConfiguration{
		"remote app":                {PublisherGroup: "production", Target: "app"},
		"remote compose":            {PublisherGroup: "production", Protocol: "postgres", Target: "compose:db:5432"},
		"remote docker":             {PublisherGroup: "production", Protocol: "tcp", Target: "docker:cache:6379"},
		"tcp app":                   {Protocol: "tcp", Target: "app"},
		"descriptor path":           {Target: "compose:../project:3000"},
		"descriptor command":        {Target: "docker:$(id):3000"},
		"descriptor args":           {Target: "compose:web:3000:extra"},
		"descriptor port":           {Target: "compose:web:65536"},
		"descriptor ambiguous port": {Target: "compose:web:03000"},
		"target TLS plaintext":      {Target: "http://upstream.internal:3000", PublicURL: &ProjectServicePublicURL{}, TargetTLS: trust},
		"target trust tamper":       {Target: "https://upstream.internal:8443", PublicURL: &ProjectServicePublicURL{}, TargetTLS: &ProjectTargetTLS{Hostname: "different.internal", CAPEM: trust.CAPEM, Digest: trust.Digest}},
		"target trust key material": {Target: "https://upstream.internal:8443", PublicURL: &ProjectServicePublicURL{}, TargetTLS: &keyTrust},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := NormalizeProjectConfiguration(ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"service": s}})
			if !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("unsafe target accepted", err)
			}
		})
	}
}

func TestNormalizeAppliedPrivateHTTPAddressesRespectTargetTrust(t *testing.T) {
	for _, test := range []struct {
		target, want string
		tls          bool
	}{
		{"https://upstream.internal", "upstream.internal:443", true},
		{"https://upstream.internal:8443", "upstream.internal:8443", true},
		{"http://upstream.internal", "upstream.internal:80", false},
		{"upstream.internal:8443", "upstream.internal:8443", false},
		{"https://[2001:db8::1]:8443", "[2001:db8::1]:8443", true},
	} {
		t.Run(test.target, func(t *testing.T) {
			service := ProjectServiceConfiguration{PublisherGroup: "production", Protocol: "http", Target: test.target}
			if test.tls {
				service.TargetTLS = appliedTargetTrust(t, "upstream.internal")
			}
			c, hash, err := NormalizeProjectConfiguration(ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"api": service}})
			if err != nil {
				t.Fatal(err)
			}
			s := c.Services["api"]
			if s.Target != test.want || (s.TargetTLS != nil) != test.tls {
				t.Fatalf("private address enabled TLS or lost its address: %+v", s)
			}
			_, retryHash, err := NormalizeProjectConfiguration(c)
			if err != nil || retryHash != hash {
				t.Fatal("private address normal form is not idempotent", err)
			}
		})
	}
	for _, target := range []string{"https://upstream.internal:8443", "https://user:secret@upstream.internal:8443", "https://upstream.internal/hooks", "https://upstream.internal?secret=value", "upstream.internal/path:8443", "user@upstream.internal:8443"} {
		if _, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"api": {Protocol: "http", Target: target}}}); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("private target accepted URL credentials, a path, or a query", err)
		}
	}
}
