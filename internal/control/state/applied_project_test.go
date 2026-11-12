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
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
)

func TestNormalizeProjectConfiguration(t *testing.T) {
	input := LocalServiceDeclaration{Target: "http://localhost:3000"}
	c, err := normalizeLocalService("web", input)
	if err != nil || c.Protocol != "http" || c.Name != "web" || c.PublicURL != nil {
		t.Fatalf("private HTTP default: %#v %v", c, err)
	}
	explicit, err := normalizeLocalService("web", LocalServiceDeclaration{Target: "http://localhost:3000", Name: "web", Protocol: "http"})
	if err != nil || !reflect.DeepEqual(explicit, c) {
		t.Fatal("defaults do not normalize to the same declaration", err)
	}
	if input.Protocol != "" {
		t.Fatal("normalization mutated caller state")
	}
	for name, declaration := range map[string]LocalServiceDeclaration{
		"public tcp":          {Target: "localhost:5432", Protocol: "postgres", PublicURL: &ProjectServicePublicURL{}},
		"target userinfo":     {Target: "http://user:secret@localhost:3000"},
		"invalid port target": {Target: "missing-port", Protocol: "tcp"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeLocalService("web", declaration); !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal(err)
			}
		})
	}
	// the logical definition has no second publisher-group schema or selectors.
	_, definitionHash, err := NormalizeServiceDefinition(ServiceDefinition{Services: map[string]ServiceDefinitionService{"web": {Protocol: "http"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		`{"services":{"web":{"protocol":"http"}},"publisher_groups":{"local":{}}}`,
		`{"services":{"web":{"protocol":"http","publisher_group":"missing"}}}`,
	} {
		if _, err := decodeServiceDefinition([]byte(data), definitionHash); !errors.Is(err, ErrServiceDefinitionInvalid) {
			t.Fatal("definition accepted retired publisher-group authority", err)
		}
	}
}

func TestNormalizeAppliedPublicOriginsMatchRuntime(t *testing.T) {
	for _, target := range []string{"http://localhost:3000", "https://EXAMPLE.test:443", "3000", "http://example.test", "https://example.test", "http://example.test:80/", "http://example.test:80#", "http://example.test:80?", "http://[2001:db8::1]:80", "http://user:secret@example.test:80", "http://example.test:0"} {
		t.Run(target, func(t *testing.T) {
			want, runtimeErr := targetsyntax.NormalizeTarget(target)
			c, err := normalizeLocalService("web", LocalServiceDeclaration{Target: target, PublicURL: &ProjectServicePublicURL{}})
			if (runtimeErr != nil) != (err != nil) || err == nil && c.Target != want {
				t.Fatal("apply and runtime disagree about public origin", c, err, runtimeErr)
			}
		})
	}
}

func TestNormalizeAppliedHTTPSettingsDoNotDisappear(t *testing.T) {
	settings := &config.HTTPService{Readiness: &config.Readiness{Path: "/health"}, Paths: map[string]config.PathMount{"/api": {Service: "api", StripPrefix: true}}}
	c, err := normalizeLocalService("web", LocalServiceDeclaration{Target: "app", PublicURL: &ProjectServicePublicURL{}, HTTP: settings})
	if err != nil || c.HTTP.Readiness.Path != "/health" || !c.HTTP.Paths["/api"].StripPrefix {
		t.Fatal("local HTTP settings lost", err)
	}
	_, hash, err := NormalizeServiceDefinition(ServiceDefinition{Services: map[string]ServiceDefinitionService{"web": {Protocol: "http"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"readiness":{"path":"/health"}`, `"paths":{"/api":{"service":"api"}}`, `"open":false`} {
		data := []byte(`{"services":{"web":{"protocol":"http","http":{` + field + `}}}}`)
		if _, err := decodeServiceDefinition(data, hash); !errors.Is(err, ErrServiceDefinitionInvalid) {
			t.Fatal("shared definition accepted local-only HTTP behavior", field, err)
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
	for name, s := range map[string]LocalServiceDeclaration{
		"local app":             {Target: "app"},
		"local compose":         {Target: "compose:postgres:5432", Protocol: "postgres"},
		"local docker":          {Target: "docker:redis_1:6379", Protocol: "tcp"},
		"local deferred public": {Target: "app", PublicURL: &ProjectServicePublicURL{Ephemeral: true}},
		"public target trust":   {Target: "https://upstream.internal:8443", PublicURL: &ProjectServicePublicURL{}, TargetTLS: trust},
		"literal docker host":   {Target: "docker:5432", Protocol: "postgres"},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := normalizeLocalService("service", s)
			if err != nil || c.Target != s.Target {
				t.Fatalf("target changed or rejected: %v", err)
			}
		})
	}
	for name, s := range map[string]LocalServiceDeclaration{
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
			_, err := normalizeLocalService("service", s)
			if !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("unsafe target accepted", err)
			}
		})
	}
	for _, service := range []EnvironmentServicePublication{
		{Protocol: "http", Target: "app"},
		{Protocol: "postgres", Target: "compose:db:5432"},
		{Protocol: "tcp", Target: "docker:cache:6379"},
	} {
		if _, err := normalizeEnvironmentService(service); !errors.Is(err, ErrEnvironmentInvalid) {
			t.Fatal("environment accepted a local-only descriptor", err)
		}
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
			service := EnvironmentServicePublication{Protocol: "http", Target: test.target}
			if test.tls {
				service.TargetTLS = appliedTargetTrust(t, "upstream.internal")
			}
			s, err := normalizeEnvironmentService(service)
			if err != nil {
				t.Fatal(err)
			}
			if s.Target != test.want || (s.TargetTLS != nil) != test.tls {
				t.Fatalf("private address enabled TLS or lost its address: %+v", s)
			}
			retry, err := normalizeEnvironmentService(s)
			if err != nil || !reflect.DeepEqual(retry, s) {
				t.Fatal("private address normal form is not idempotent", err)
			}
		})
	}
	for _, target := range []string{"https://upstream.internal:8443", "https://user:secret@upstream.internal:8443", "https://upstream.internal/hooks", "https://upstream.internal?secret=value", "upstream.internal/path:8443", "user@upstream.internal:8443"} {
		if _, err := normalizeEnvironmentService(EnvironmentServicePublication{Protocol: "http", Target: target}); !errors.Is(err, ErrEnvironmentInvalid) {
			t.Fatal("private target accepted URL credentials, a path, or a query", err)
		}
	}
}
