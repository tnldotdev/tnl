package machineproof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func sourceChallenge(operation string) authorityv1.IdentitySourceChallenge {
	const suffix = "0123456789ABCDEFGHIJKL"
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32)).Public().(ed25519.PublicKey)
	c := authorityv1.IdentitySourceChallenge{Schema: 1, Id: strings.Repeat("a", 32), BindingDigest: strings.Repeat("b", 64), Source: authorityv1.IdentitySourceSelection{Kind: "registered_key", MachineId: "mci_" + suffix, KeyId: "source-key"}, Server: "https://control.example", Operation: authorityv1.IdentitySourceChallengeOperation(operation), ExpiresAt: time.Now().Add(30 * time.Second), NativePublicKey: base64.RawURLEncoding.EncodeToString(public)}
	switch operation {
	case "publication_exchange", "publication_refresh":
		c.Publication = &authorityv1.IdentitySourcePublicationSelection{Namespace: "apps.example"}
		op, nonce := "exchange", strings.Repeat("n", 32)
		c.Nonce = nonce
		c.Audience = c.Server + "/v1/machine-publication-sessions/exchange"
		if operation == "publication_refresh" {
			op, nonce = "refresh", "mps_"+suffix
			c.Nonce = ""
			c.SessionId = nonce
			c.Audience = c.Server + "/v1/machine-publication-sessions/" + nonce + "/refresh"
		}
		c.Scope = Publication("", c.Publication.Namespace, op, c.NativePublicKey, nonce)
	case "visitor_prepare", "visitor_attach":
		c.Selection = &authorityv1.IdentitySourceVisitorSelection{Environment: controlv1.EnvironmentReference{Server: c.Server, ProjectKey: "project", EnvironmentId: "env_" + suffix}, PermissionId: "mwp_" + suffix, Services: map[string]controlv1.ServiceProtocol{"orders": "postgres"}}
		op, nonce := "prepare", strings.Repeat("n", 32)
		c.Nonce = nonce
		c.Audience = c.Server + "/v1/projects/project/environments/" + c.Selection.Environment.EnvironmentId + "/visitors/prepare"
		if operation == "visitor_attach" {
			op, nonce = "attach", "wls_"+suffix
			c.Nonce = ""
			c.SessionId = nonce
			c.Audience = c.Server + "/v1/environment-visitor-sessions/" + nonce + "/assertions"
		}
		c.Scope = EnvironmentVisitor(c.Selection.PermissionId, c.Selection.Environment.EnvironmentId, op, c.NativePublicKey, nonce, map[string]string{"orders": "postgres"})
	}
	return c
}

func TestIdentitySourceChallengeValidatesPublicationAndActualVisitorFacts(t *testing.T) {
	for _, operation := range []string{"publication_exchange", "publication_refresh", "visitor_prepare", "visitor_attach"} {
		t.Run(operation, func(t *testing.T) {
			c := sourceChallenge(operation)
			if err := ValidateSourceChallenge(c, time.Now()); err != nil {
				t.Fatal(err)
			}
			for name, change := range map[string]func(*authorityv1.IdentitySourceChallenge){
				"native key": func(c *authorityv1.IdentitySourceChallenge) { c.NativePublicKey = strings.Repeat("a", 43) },
				"audience":   func(c *authorityv1.IdentitySourceChallenge) { c.Audience += "/other" },
				"scope":      func(c *authorityv1.IdentitySourceChallenge) { c.Scope = strings.Repeat("a", 64) },
				"operation":  func(c *authorityv1.IdentitySourceChallenge) { c.Operation = "other" },
				"nonce or session": func(c *authorityv1.IdentitySourceChallenge) {
					if c.Nonce != "" {
						c.Nonce = strings.Repeat("z", 32)
					} else {
						c.SessionId = "wls_1123456789ABCDEFGHIJKL"
					}
				},
				"expired":   func(c *authorityv1.IdentitySourceChallenge) { c.ExpiresAt = time.Now().Add(-time.Second) },
				"unbounded": func(c *authorityv1.IdentitySourceChallenge) { c.ExpiresAt = time.Now().Add(2 * time.Minute) },
				"selection": func(c *authorityv1.IdentitySourceChallenge) {
					if c.Selection != nil {
						s := *c.Selection
						s.PermissionId = "mwp_1123456789ABCDEFGHIJKL"
						c.Selection = &s
					} else {
						p := *c.Publication
						p.Namespace = "other.example"
						c.Publication = &p
					}
				},
			} {
				t.Run(name, func(t *testing.T) {
					changed := c
					change(&changed)
					if ValidateSourceChallenge(changed, time.Now()) == nil {
						t.Fatal("changed source challenge facts accepted")
					}
				})
			}
		})
	}
}
