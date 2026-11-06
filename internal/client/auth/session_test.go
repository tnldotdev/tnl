package auth

import (
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestAuthoritySessionConvertsOnlyValidatedCredentials(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	r := authorityv1.ControlSessionResponse{SessionId: "cs_0123456789abcdefghijkl", AccessToken: access.String(), RefreshToken: refresh.String(), AccessExpiresAt: time.Now().Add(time.Hour), RefreshExpiresAt: time.Now().Add(24 * time.Hour)}
	got, err := authoritySession(r, "", time.Time{})
	want := clientstate.ControlSession{SessionID: r.SessionId, AccessToken: r.AccessToken, RefreshToken: r.RefreshToken, AccessExpiresAt: r.AccessExpiresAt, RefreshExpiresAt: r.RefreshExpiresAt}
	if err != nil || got != want {
		t.Fatalf("native session conversion changed validated fields: %v", err)
	}
	r.AccessToken = "invalid"
	if got, err := authoritySession(r, "", time.Time{}); err == nil || got != (clientstate.ControlSession{}) {
		t.Fatal("invalid response exposed native session credentials")
	}
}
