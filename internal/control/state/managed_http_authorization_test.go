package controlstate

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/httpsubject"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestManagedHTTPRunCredentialBoundary(t *testing.T) {
	run := ManagedHTTPRun{Subject: httpsubject.Subject{Kind: httpsubject.ManagedService, ID: "psvc_" + strings.Repeat("A", 22)}, RunID: "psrun_" + strings.Repeat("A", 22), Number: 1, Token: credentials.ManagedRunToken(strings.Repeat("A", 43))}
	if !run.valid() {
		t.Fatal("canonical managed run credential was rejected")
	}
	publicToken, _, _, err := credentials.NewPublishRunToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", publicToken.String(), run.Token.String() + "=", strings.Repeat("A", 42) + "B"} {
		invalid := run
		invalid.Token = credentials.ManagedRunToken(token)
		if invalid.valid() {
			t.Fatal("public or noncanonical token authorized a managed HTTP run")
		}
	}
	public := run
	public.Subject = httpsubject.Subject{Kind: httpsubject.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
	if public.valid() {
		t.Fatal("managed token authorized a public URL subject")
	}
}

func TestManagedHTTPCredentialBoundary(t *testing.T) {
	secret := strings.Repeat("A", 43)
	grant := "mhg_" + strings.Repeat("A", 22) + "." + secret
	certificate := []byte("certificate payload verified by certificate API")
	for _, tc := range []struct {
		name  string
		input controlv1.ManagedHTTPCredential
		valid bool
	}{
		{"none", controlv1.ManagedHTTPCredential{Kind: "none"}, true},
		{"browser", controlv1.ManagedHTTPCredential{Kind: "browser", Secret: &secret}, true},
		{"token", controlv1.ManagedHTTPCredential{Kind: "token", Secret: &grant}, true},
		{"share", controlv1.ManagedHTTPCredential{Kind: "share", Secret: &grant}, true},
		{"certificate", controlv1.ManagedHTTPCredential{Kind: "certificate", Certificate: &certificate}, true},
		{"unknown", controlv1.ManagedHTTPCredential{Kind: "other", Secret: &secret}, false},
		{"missing token", controlv1.ManagedHTTPCredential{Kind: "token"}, false},
		{"none with secret", controlv1.ManagedHTTPCredential{Kind: "none", Secret: &secret}, false},
		{"none with certificate", controlv1.ManagedHTTPCredential{Kind: "none", Certificate: &certificate}, false},
		{"certificate with secret", controlv1.ManagedHTTPCredential{Kind: "certificate", Certificate: &certificate, Secret: &secret}, false},
		{"secret with certificate", controlv1.ManagedHTTPCredential{Kind: "token", Certificate: &certificate, Secret: &grant}, false},
		{"unscoped grant", controlv1.ManagedHTTPCredential{Kind: "share", Secret: &secret}, false},
		{"scoped browser", controlv1.ManagedHTTPCredential{Kind: "browser", Secret: &grant}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credential, err := parseManagedHTTPCredential(tc.input)
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
				restored, err := storedManagedHTTPCredential(string(credential.kind), credential.digest[:])
				if err != nil || restored.digest != credential.digest || restored.kind != credential.kind {
					t.Fatal("stored credential lost validated kind or digest")
				}
			}
		})
	}
	for _, kind := range []string{"none", "certificate", "unknown"} {
		if _, err := storedManagedHTTPCredential(kind, make([]byte, 32)); err == nil {
			t.Fatal("stored digest selected a non-secret credential")
		}
	}
	for _, size := range []int{0, 31, 33} {
		if _, err := storedManagedHTTPCredential("browser", make([]byte, size)); err == nil {
			t.Fatal("invalid stored credential digest length accepted")
		}
	}
}

func TestManagedHTTPCredentialHashVectors(t *testing.T) {
	secret := strings.Repeat("A", 43)
	grant := "mhg_" + strings.Repeat("A", 22) + "." + secret
	for _, tc := range []struct{ kind, secret, digest string }{
		{"browser", secret, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},
		{"token", grant, "ed880e6332653683e761e4457f323b1c0bbe372fc1324cd6c1447ba21e79a3ce"},
		{"share", grant, "ed880e6332653683e761e4457f323b1c0bbe372fc1324cd6c1447ba21e79a3ce"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			actual, err := managedHTTPDigest(tc.kind, tc.secret)
			if err != nil || hex.EncodeToString(actual) != tc.digest {
				t.Fatalf("stored credential hash bytes changed: %v", err)
			}
		})
	}
	for _, raw := range []string{grant + "=", strings.Replace(grant, "mhg_", "url_", 1), grant[:len(grant)-1] + "B", grant + ".extra"} {
		if _, err := managedHTTPDigest("token", raw); err == nil {
			t.Fatal("noncanonical grant payload accepted")
		}
	}
}
