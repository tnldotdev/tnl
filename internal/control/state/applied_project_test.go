package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestNormalizeProjectConfiguration(t *testing.T) {
	input := ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {Target: "http://localhost:3000"}}}
	c, hash, err := NormalizeProjectConfiguration(input)
	if err != nil || c.Services["web"].Protocol != "http" || c.Settings != nil || projectServicePublic(c.Services["web"]) {
		t.Fatalf("private HTTP default: %#v %v", c, err)
	}
	_, hash2, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {Target: "http://localhost:3000", Name: "web", Protocol: "http"}}})
	if err != nil || hash2 != hash {
		t.Fatal("defaults do not normalize to the same hash", err)
	}
	if input.Services["web"].Protocol != "" {
		t.Fatal("normalization mutated caller state")
	}
	for name, c := range map[string]ProjectConfiguration{
		"invalid settings":    {Settings: &DeploymentSettings{Description: "invalid\rdescription"}},
		"invalid hostname":    {Services: map[string]ProjectServiceConfiguration{"db": {Target: "localhost:5432", Protocol: "postgres", Hostname: "UPPER.example.test"}}},
		"target userinfo":     {Services: map[string]ProjectServiceConfiguration{"web": {Target: "http://user:secret@localhost:3000"}}},
		"invalid port target": {Services: map[string]ProjectServiceConfiguration{"db": {Target: "missing-port", Protocol: "tcp"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := NormalizeProjectConfiguration(c); !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal(err)
			}
		})
	}
	for _, invalid := range []string{
		`{"unknown":{}}`,
		`{"services":{"db":{"unknown":true}}}`,
		`{"services":{"web":{"target":"app","public_url":{}}}}`,
	} {
		var c ProjectConfiguration
		decoder := json.NewDecoder(strings.NewReader(invalid))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&c); err == nil {
			t.Fatal("configuration accepted an unknown field")
		}
	}
}

func TestNormalizeAppliedPublicOriginsMatchRuntime(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, test := range []struct{ target, want string }{
			{"http://localhost:3000", "localhost:3000"}, {"https://EXAMPLE.test:443", "EXAMPLE.test:443"},
			{"3000", ""}, {"http://example.test", "example.test:80"}, {"https://example.test", "example.test:443"},
			{"http://example.test:80/", ""}, {"http://example.test:80#", ""},
			{"http://example.test:80?", ""}, {"http://[2001:db8::1]:80", "[2001:db8::1]:80"},
			{"http://user:secret@example.test:80", ""}, {"http://example.test:0", ""},
		} {
			t.Run(fmt.Sprintf("%s/public=%t", test.target, public), func(t *testing.T) {
				service := ProjectServiceConfiguration{Target: test.target, Public: new(public)}
				if strings.HasPrefix(test.target, "https://") {
					service.TargetTLS = appliedTargetTrust(t, "upstream.internal")
				}
				c, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": service}})
				if (test.want == "") != (err != nil) || err == nil && c.Services["web"].Target != test.want {
					t.Fatal("public reachability changed service target normalization", c, err)
				}
			})
		}
	}
}

func TestNormalizeAppliedServicePublicationFields(t *testing.T) {
	domain := mustOpaqueID(t, opaqueid.DomainPrefix)
	for _, protocol := range []string{"http", "tcp", "postgres"} {
		t.Run(protocol, func(t *testing.T) {
			service := ProjectServiceConfiguration{Protocol: protocol, Target: "localhost:3000",
				Hostname: "app.example.test", DomainID: domain, Ephemeral: true, RequirePostQuantum: new(false),
				Traffic: &trafficlimits.Selection{Connections: new(4), TotalConnections: new(int64(0))}}
			c, hash, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"app": service}})
			if err != nil {
				t.Fatal(err)
			}
			got := c.Services["app"]
			if got.Hostname != service.Hostname || got.DomainID != domain || !got.Ephemeral || got.RequirePostQuantum == nil || *got.RequirePostQuantum || got.Traffic == nil || *got.Traffic.Connections != 4 || *got.Traffic.TotalConnections != 0 || projectServicePublic(got) {
				t.Fatal("direct publication settings were lost or enabled ingress", got)
			}
			if _, retry, err := NormalizeProjectConfiguration(c); err != nil || retry != hash {
				t.Fatal("direct publication settings do not normalize idempotently", err)
			}
		})
	}
	for name, service := range map[string]ProjectServiceConfiguration{
		"domain":  {Target: "app", DomainID: "not-a-domain"},
		"traffic": {Target: "app", Traffic: &trafficlimits.Selection{TotalConnections: new(int64(config.MaxConfigInteger + 1))}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"app": service}}); !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("invalid direct publication setting accepted", err)
			}
		})
	}
}

func TestNormalizeAppliedHTTPSettingsDoNotDisappear(t *testing.T) {
	settings := &config.HTTPService{Readiness: &config.Readiness{Path: "/health"}, Paths: map[string]config.PathMount{"/api": {Service: "api", StripPrefix: true}}}
	c, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {Target: "app", Public: new(true), HTTP: settings}, "api": {Target: "http://localhost:3001"}}})
	if err != nil || c.Services["web"].HTTP.Readiness.Path != "/health" || !c.Services["web"].HTTP.Paths["/api"].StripPrefix {
		t.Fatal("local HTTP settings lost", err)
	}
	for _, s := range []*config.HTTPService{{Readiness: &config.Readiness{Path: "/health"}}, {Paths: map[string]config.PathMount{"/api": {Service: "api"}}}, {Open: new(bool)}} {
		_, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{"web": {Target: "http://app.internal:3000", HTTP: s}}})
		if !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("unsupported remote HTTP behavior accepted", err)
		}
	}
}

func TestLocalServiceNormalizationDoesNotInventProjectDestinations(t *testing.T) {
	service := func(prefix, destination string) ProjectServiceConfiguration {
		return ProjectServiceConfiguration{Target: "app", HTTP: &config.HTTPService{
			Paths: map[string]config.PathMount{prefix: {Service: destination}},
		}}
	}
	single := service("/api", "api")
	if err := normalizeAppliedProjectService("web", &single, true); err != nil || single.Name != "web" || single.Protocol != "http" {
		t.Fatal("one binding could not normalize without fabricated siblings", single, err)
	}
	if _, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": single}}); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("whole project accepted a missing path destination", err)
	}
	for _, invalid := range []ProjectServiceConfiguration{
		service("/__tnl/hooks", "api"), service("/api", "web"), service("/api", "invalid name"), service("api", "api"),
	} {
		if err := normalizeAppliedProjectService("web", &invalid, true); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("single-binding normalization lost path bounds", err)
		}
	}
	for _, destination := range []ProjectServiceConfiguration{
		{Protocol: "tcp", Target: "localhost:3001"},
		{Protocol: "postgres", Target: "localhost:5432"},
	} {
		if _, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": single, "api": destination}}); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("project boundary accepted a non-HTTP path destination", err)
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
	withoutDigest := *trust
	withoutDigest.Digest = ""
	derived, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {Target: "https://upstream.internal:8443", Public: new(true), TargetTLS: &withoutDigest}}})
	if err != nil || derived.Services["web"].TargetTLS.Digest != trust.Digest || withoutDigest.Digest != "" {
		t.Fatal("control did not derive the existing project digest without mutating input", err)
	}
	keyTrust := *trust
	keyTrust.CAPEM = "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----"
	keyDigest := sha256.Sum256([]byte("tnl-target-tls/v1\x00" + keyTrust.Hostname + "\x00" + keyTrust.CAPEM))
	keyTrust.Digest = hex.EncodeToString(keyDigest[:])
	for name, s := range map[string]ProjectServiceConfiguration{
		"local app":                  {Target: "app"},
		"local compose":              {Target: "compose:postgres:5432", Protocol: "postgres"},
		"local docker":               {Target: "docker:redis_1:6379", Protocol: "tcp"},
		"local deferred public":      {Target: "app", Public: new(true), Ephemeral: true},
		"public target trust":        {Target: "https://upstream.internal:8443", Public: new(true), TargetTLS: trust},
		"public uppercase trust":     {Target: "HTTPS://upstream.internal:8443", Public: new(true), TargetTLS: trust},
		"remote app":                 {Target: "app"},
		"remote literal docker host": {Target: "docker:5432", Protocol: "postgres"},
	} {
		t.Run(name, func(t *testing.T) {
			input := ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"service": s}}
			if strings.HasPrefix(name, "remote ") {
				input.Settings = &DeploymentSettings{}
			}
			c, _, err := NormalizeProjectConfiguration(input)
			want := s.Target
			if strings.HasPrefix(strings.ToLower(want), "https://") {
				want = "upstream.internal:8443"
			}
			if err != nil || c.Services["service"].Target != want {
				t.Fatalf("target changed or rejected: %v", err)
			}
		})
	}
	for name, s := range map[string]ProjectServiceConfiguration{
		"remote ephemeral app":      {Target: "app", Ephemeral: true},
		"remote compose":            {Protocol: "postgres", Target: "compose:db:5432"},
		"remote docker":             {Protocol: "tcp", Target: "docker:cache:6379"},
		"tcp app":                   {Protocol: "tcp", Target: "app"},
		"descriptor path":           {Target: "compose:../project:3000"},
		"descriptor command":        {Target: "docker:$(id):3000"},
		"descriptor args":           {Target: "compose:web:3000:extra"},
		"descriptor port":           {Target: "compose:web:65536"},
		"descriptor ambiguous port": {Target: "compose:web:03000"},
		"target TLS plaintext":      {Target: "http://upstream.internal:3000", Public: new(true), TargetTLS: trust},
		"uppercase TLS plaintext":   {Target: "HTTP://upstream.internal:3000", Public: new(true), TargetTLS: trust},
		"uppercase TLS missing":     {Target: "HTTPS://upstream.internal:8443", Public: new(true)},
		"target trust tamper":       {Target: "https://upstream.internal:8443", Public: new(true), TargetTLS: &ProjectTargetTLS{Hostname: "different.internal", CAPEM: trust.CAPEM, Digest: trust.Digest}},
		"target trust key material": {Target: "https://upstream.internal:8443", Public: new(true), TargetTLS: &keyTrust},
	} {
		t.Run(name, func(t *testing.T) {
			input := ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"service": s}}
			if strings.HasPrefix(name, "remote ") {
				input.Settings = &DeploymentSettings{}
			}
			_, _, err := NormalizeProjectConfiguration(input)
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
			service := ProjectServiceConfiguration{Protocol: "http", Target: test.target}
			if test.tls {
				service.TargetTLS = appliedTargetTrust(t, "upstream.internal")
			}
			c, hash, err := NormalizeProjectConfiguration(ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{"api": service}})
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
