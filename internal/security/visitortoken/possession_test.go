package visitortoken

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestDurableBearerUsesAdvertisedLifetimeAndCurrentExactAuthority(t *testing.T) {
	for _, kind := range []string{"share", "service token", "service share"} {
		t.Run(kind, func(t *testing.T) {
			_, _, view, now := tokenFixture(t)
			until := now.Add(7 * 24 * time.Hour)
			secret := bytes.Repeat([]byte{7}, 32)
			var token Token
			var digest [32]byte
			install := func(v View, deadline time.Time) View {
				if kind == "share" {
					return v.WithShareVerifiers(map[string]ShareVerifier{"shr_" + strings.Repeat("A", 22): {Digest: digest, ExpiresAt: deadline}})
				}
				grantKind := "token"
				if kind == "service share" {
					grantKind = "share"
				}
				return v.WithGrantVerifiers(map[string]GrantVerifier{"shg_" + strings.Repeat("A", 22): {Digest: digest, Kind: grantKind, ExpiresAt: deadline}})
			}
			if kind == "share" {
				token, _ = ShareToken("shr_"+strings.Repeat("A", 22), secret)
				digest = sha256.Sum256(secret)
			} else {
				view.Scope = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
				view.Port = 25443
				token, _ = GrantToken("shg_"+strings.Repeat("A", 22), secret)
				_, digest, _ = GrantTokenDigest(token)
			}
			view = install(view, until)
			permission, err := VerifyBearer(token, view, now)
			if err != nil || !permission.Valid() {
				t.Fatal("durable bearer denied", err)
			}
			for _, elapsed := range []time.Duration{6 * time.Minute, 25 * time.Hour, 7*24*time.Hour - time.Microsecond} {
				at := now.Add(elapsed)
				view.VisitorPolicyRevision++
				view.ObservedAt, view.ValidUntil = at, at.Add(PolicyLifetime)
				view = view.WithVerificationKeys(nil)
				if _, err := VerifyBearer(token, view, at); err != nil {
					t.Fatal("original bearer needed replacement", err)
				}
				if err := CheckCurrent(permission, view, at); err != nil {
					t.Fatal("unrelated policy/key revision revoked bearer", err)
				}
			}
			at := view.ObservedAt
			shortDeadline := until.Add(-500 * time.Nanosecond)
			short := install(view, shortDeadline)
			if !PermissionDeadline(permission, short).Equal(shortDeadline) {
				t.Fatal("shortened current deadline ignored")
			}
			for _, fault := range []string{"revoked", "wrong digest", "wrong resource", "wrong hostname", "wrong port", "expired parent"} {
				other := view
				switch fault {
				case "revoked":
					other = other.WithShareVerifiers(nil).WithGrantVerifiers(nil)
				case "wrong digest":
					digest[0] ^= 1
					other = install(other, until)
					digest[0] ^= 1
				case "wrong resource":
					other.Scope.ID = strings.Replace(other.Scope.ID, "A", "B", 1)
					other = other.WithShareVerifiers(nil).WithGrantVerifiers(nil)
				case "wrong hostname":
					other.Hostname = "other.example.test"
				case "wrong port":
					other.Port++
				case "expired parent":
					other = install(other, at)
				}
				if err := CheckCurrent(permission, other, at); err == nil {
					t.Fatal(fault, "retained admitted permission")
				}
				if fault != "wrong hostname" && fault != "wrong port" {
					if _, err := VerifyBearer(token, other, at); err == nil {
						t.Fatal(fault, "accepted bearer")
					}
				}
			}
			if _, err := VerifyBearer(token, view, view.ValidUntil); !errors.Is(err, ErrPolicy) {
				t.Fatal("policy outage retained admission", err)
			}
			view.ObservedAt, view.ValidUntil = until, until.Add(PolicyLifetime)
			if _, err := VerifyBearer(token, view, until); !errors.Is(err, ErrToken) {
				t.Fatal("expiry boundary extended credential", err)
			}
			view.ObservedAt, view.ValidUntil = until.Add(-time.Second), until.Add(PolicyLifetime-time.Second)
			for _, formatted := range []string{fmt.Sprint(token), fmt.Sprintf("%+v", token), fmt.Sprintf("%#v", token)} {
				if strings.Contains(formatted, token.Reveal()) {
					t.Fatal("incidental formatting leaked token")
				}
			}
			for _, raw := range []string{"", token.Reveal() + "=", token.Reveal() + ".extra", token.Reveal()[:len(token)-1] + "B", "vsg1.invalid." + strings.Repeat("A", 43), strings.Repeat("a", MaxTokenBytes+1)} {
				if _, err := VerifyBearer(Token(raw), view, until.Add(-time.Microsecond)); err == nil {
					t.Fatal("malformed bearer accepted")
				}
			}
		})
	}
}
