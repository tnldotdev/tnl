package oidc_test

import (
	"encoding/base64"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/oidc"
)

func TestWorkloadHintIsUnverifiedAndBounded(t *testing.T) {
	unsigned := func(payload string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".untrusted"
	}
	for _, aud := range []string{`"tnl"`, `["tnl"]`} {
		h, err := oidc.UnverifiedWorkloadIdentity(unsigned(`{"iss":"https://issuer.example","sub":"machine","aud":` + aud + `,"jwks_uri":"https://attacker.example/keys"}`))
		if err != nil || h.Issuer != "https://issuer.example" || h.Subject != "machine" || h.Audience != "tnl" {
			t.Fatal(h, err)
		}
	}
	for _, payload := range []string{`{}`, `{"iss":"http://issuer.example","sub":"machine","aud":"tnl"}`, `{"iss":"https://issuer.example","sub":"machine","aud":["tnl","other"]}`, `{"iss":"https://issuer.example","sub":"*","aud":"tnl"}`, `{"iss":"https://issuer.example","sub":"machine","aud":null}`} {
		if _, err := oidc.UnverifiedWorkloadIdentity(unsigned(payload)); err == nil {
			t.Fatal("invalid hint accepted", payload)
		}
	}
	if _, err := oidc.UnverifiedWorkloadIdentity("invalid"); err == nil {
		t.Fatal("invalid compact JWT accepted")
	}
}
