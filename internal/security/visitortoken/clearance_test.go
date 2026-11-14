package visitortoken

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestClearanceIsNotVisitorAuthorization(t *testing.T) {
	key, permission, view, now := tokenFixture(t)
	expires := now.Add(ClearanceLifetime)
	clearance, err := SignClearance(view.Issuer, "key-one", key, Clearance{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, ExpiresAt: expires}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyClearance(clearance, view, now); err != nil || !got.Equal(expires) {
		t.Fatal("valid clearance was rejected", got, err)
	}
	if _, err := VerifyBearer(Token(clearance.Reveal()), view, now); !errors.Is(err, ErrToken) {
		t.Fatal("challenge clearance granted visitor access", err)
	}
	auth := issueToken(t, key, permission, view, now)
	if _, err := VerifyClearance(ClearanceToken(auth.Reveal()), view, now); !errors.Is(err, ErrToken) {
		t.Fatal("visitor permission bypassed the challenge", err)
	}
	if fmt.Sprint(clearance) != "challenge clearance" || fmt.Sprintf("%#v", clearance) != "challenge clearance" {
		t.Fatal("incidental formatting revealed clearance")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(clearance.Reveal(), ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"visitor", "visitor_policy_revision", "run_id", "run_number", "source_ip", "waf", "git"} {
		if _, present := fields[name]; present {
			t.Fatal("clearance captured authorization, run, or configuration state", name)
		}
	}
	// a new run or WAF edit may use another current policy revision, but the
	// original clearance retains its absolute deadline rather than renewing.
	later := now.Add(15 * time.Minute)
	view.VisitorPolicyRevision++
	view.MetadataRevision++
	view.ObservedAt, view.ValidUntil = later, later.Add(PolicyLifetime)
	if got, err := VerifyClearance(clearance, view, later); err != nil || !got.Equal(expires) {
		t.Fatal("a current replacement policy invalidated or extended clearance", got, err)
	}
	view.ObservedAt, view.ValidUntil = expires, expires.Add(PolicyLifetime)
	if _, err := VerifyClearance(clearance, view, expires); !errors.Is(err, ErrToken) {
		t.Fatal("absolute clearance expiry was extended", err)
	}
}

func TestClearanceBindsExactResourceOriginPurposeAndIssuer(t *testing.T) {
	key, _, original, now := tokenFixture(t)
	for _, kind := range []visitorscope.Kind{visitorscope.PublicURL, visitorscope.Service} {
		view := original
		if kind == visitorscope.Service {
			view.Scope = visitorscope.Scope{Kind: kind, ID: "svc_" + strings.Repeat("A", 22)}
			view.Port = 25443
		}
		token, err := SignClearance(view.Issuer, "key-one", key, Clearance{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, ExpiresAt: now.Add(ClearanceLifetime)}, now)
		if err != nil {
			t.Fatal(err)
		}
		for name, mutate := range map[string]func(*View){
			"resource":   func(v *View) { v.Scope.ID = strings.ReplaceAll(v.Scope.ID, "A", "B") },
			"hostname":   func(v *View) { v.Hostname = "another.example.test" },
			"port":       func(v *View) { v.Port++ },
			"issuer":     func(v *View) { v.Issuer = "https://another-control.example.test" },
			"stale keys": func(v *View) { v.ValidUntil = now },
		} {
			changed := view
			mutate(&changed)
			if _, err := VerifyClearance(token, changed, now); err == nil {
				t.Fatal("clearance ignored binding", kind, name)
			}
		}
		parts := strings.Split(token.Reveal(), ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		for name, mutate := range map[string]func(*clearanceClaims){
			"purpose":             func(c *clearanceClaims) { c.Purpose = "visitor" },
			"version":             func(c *clearanceClaims) { c.Version++ },
			"nonce":               func(c *clearanceClaims) { c.ID = "" },
			"future":              func(c *clearanceClaims) { c.Issued = now.Add(time.Second).Unix() },
			"too long":            func(c *clearanceClaims) { c.Expires++ },
			"noncanonical origin": func(c *clearanceClaims) { c.Origin += "/" },
		} {
			var claims clearanceClaims
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatal(err)
			}
			mutate(&claims)
			raw, _ := json.Marshal(claims)
			signed, err := signCredential(ClearanceType, "key-one", key, raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyClearance(ClearanceToken(signed), view, now); !errors.Is(err, ErrToken) {
				t.Fatal("accepted invalid signed clearance claims", name, err)
			}
		}
	}
}
