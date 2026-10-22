package state

import "testing"

func TestPublicURLCreateTargetShape(t *testing.T) {
	if !PublicURLServiceHTTP.ValidCreateTarget(PublicURLPurposeApp, "", false) {
		t.Fatal("saved HTTP publisher-local target rejected")
	}
	for _, protocol := range []PublicURLServiceProtocol{"ssh", "postgres", "mysql", "redis", "tcp"} {
		if protocol.Valid() || protocol.ValidCreateTarget(PublicURLPurposeApp, "", false) || protocol.ValidCreateTarget(PublicURLPurposeApp, "http://127.0.0.1:3000", false) {
			t.Errorf("private protocol %q accepted as a public URL", protocol)
		}
	}
	if PublicURLServiceHTTP.ValidCreateTarget(PublicURLPurposeApp, "", true) {
		t.Fatal("ephemeral HTTP empty target accepted")
	}
	if !PublicURLServiceHTTP.ValidCreateTarget(PublicURLPurposeApp, "http://127.0.0.1:3000", true) {
		t.Fatal("ephemeral HTTP target rejected")
	}
	for _, purpose := range []PublicURLPurpose{PublicURLPurposeApp, PublicURLPurposeAlias, PublicURLPurposeDemo, PublicURLPurposeOAuth, PublicURLPurposeWebhooks, "", "unknown"} {
		for _, ephemeral := range []bool{false, true} {
			want := !ephemeral && (purpose == PublicURLPurposeApp || purpose == PublicURLPurposeAlias)
			if got := PublicURLServiceHTTP.ValidCreateTarget(purpose, "", ephemeral); got != want {
				t.Errorf("targetless %q ephemeral=%t: got %t, want %t", purpose, ephemeral, got, want)
			}
			if got := PublicURLServiceHTTP.ValidCreateTarget(purpose, "http://127.0.0.1:3000", ephemeral); got != purpose.ValidForCreation() {
				t.Errorf("HTTP target for %q ephemeral=%t: got %t", purpose, ephemeral, got)
			}
		}
	}
}
