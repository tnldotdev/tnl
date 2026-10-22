package state

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/httpsubject"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPRunCredentialBoundary(t *testing.T) {
	run := ServiceHTTPRun{Subject: httpsubject.Subject{Kind: httpsubject.Service, ID: "svc_" + strings.Repeat("A", 22)}, RunID: "srun_" + strings.Repeat("A", 22), Number: 1, Token: credentials.ServiceRunToken(strings.Repeat("A", 43))}
	if !run.valid() {
		t.Fatal("canonical managed run credential was rejected")
	}
	publicToken, _, _, err := credentials.NewPublishRunToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", publicToken.String(), run.Token.String() + "=", strings.Repeat("A", 42) + "B"} {
		invalid := run
		invalid.Token = credentials.ServiceRunToken(token)
		if invalid.valid() {
			t.Fatal("public or noncanonical token authorized a service HTTP run")
		}
	}
	public := run
	public.Subject = httpsubject.Subject{Kind: httpsubject.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
	if public.valid() {
		t.Fatal("managed token authorized a public URL subject")
	}
}

func TestServiceHTTPCredentialBoundary(t *testing.T) {
	secret := strings.Repeat("A", 43)
	grant := "shg_" + strings.Repeat("A", 22) + "." + secret
	certificate := []byte("certificate payload verified by certificate API")
	for _, tc := range []struct {
		name  string
		input controlv1.ServiceHTTPCredential
		valid bool
	}{
		{"none", controlv1.ServiceHTTPCredential{Kind: "none"}, true},
		{"browser", controlv1.ServiceHTTPCredential{Kind: "browser", Secret: &secret}, true},
		{"token", controlv1.ServiceHTTPCredential{Kind: "token", Secret: &grant}, true},
		{"share", controlv1.ServiceHTTPCredential{Kind: "share", Secret: &grant}, true},
		{"certificate", controlv1.ServiceHTTPCredential{Kind: "certificate", Certificate: &certificate}, true},
		{"unknown", controlv1.ServiceHTTPCredential{Kind: "other", Secret: &secret}, false},
		{"missing token", controlv1.ServiceHTTPCredential{Kind: "token"}, false},
		{"none with secret", controlv1.ServiceHTTPCredential{Kind: "none", Secret: &secret}, false},
		{"none with certificate", controlv1.ServiceHTTPCredential{Kind: "none", Certificate: &certificate}, false},
		{"certificate with secret", controlv1.ServiceHTTPCredential{Kind: "certificate", Certificate: &certificate, Secret: &secret}, false},
		{"secret with certificate", controlv1.ServiceHTTPCredential{Kind: "token", Certificate: &certificate, Secret: &grant}, false},
		{"unscoped grant", controlv1.ServiceHTTPCredential{Kind: "share", Secret: &secret}, false},
		{"scoped browser", controlv1.ServiceHTTPCredential{Kind: "browser", Secret: &grant}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credential, err := parseServiceHTTPCredential(tc.input)
			if (err == nil) != tc.valid {
				t.Fatalf("credential selection: %v", err)
			}
			if !tc.valid {
				return
			}
			if string(credential.kind) != string(tc.input.Kind) {
				t.Fatal("selected credential changed kind")
			}
			if credential.kind.secret() {
				restored, err := storedServiceHTTPCredential(string(credential.kind), credential.digest[:])
				if err != nil || restored.digest != credential.digest || restored.kind != credential.kind {
					t.Fatal("stored credential lost validated kind or digest")
				}
			}
		})
	}
	for _, kind := range []string{"none", "certificate", "unknown"} {
		if _, err := storedServiceHTTPCredential(kind, make([]byte, 32)); err == nil {
			t.Fatal("stored digest selected a non-secret credential")
		}
	}
	for _, size := range []int{0, 31, 33} {
		if _, err := storedServiceHTTPCredential("browser", make([]byte, size)); err == nil {
			t.Fatal("invalid stored credential digest length accepted")
		}
	}
}

func TestServiceHTTPCredentialHashVectors(t *testing.T) {
	secret := strings.Repeat("A", 43)
	grant := "shg_" + strings.Repeat("A", 22) + "." + secret
	for _, tc := range []struct{ kind, secret, digest string }{
		{"browser", secret, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},
		{"token", grant, "97c92dad360b45e0845a2602903ceb924d43ba0aac1356809a0918132a2ebffe"},
		{"share", grant, "97c92dad360b45e0845a2602903ceb924d43ba0aac1356809a0918132a2ebffe"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			actual, err := serviceHTTPDigest(tc.kind, tc.secret)
			if err != nil || hex.EncodeToString(actual) != tc.digest {
				t.Fatalf("stored credential hash bytes changed: %v", err)
			}
		})
	}
	for _, raw := range []string{grant + "=", strings.Replace(grant, "shg_", "url_", 1), grant[:len(grant)-1] + "B", grant + ".extra"} {
		if _, err := serviceHTTPDigest("token", raw); err == nil {
			t.Fatal("noncanonical grant payload accepted")
		}
	}
}
