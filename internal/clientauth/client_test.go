package clientauth

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestAuthoritySessionValidatesIssuedTokens(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	stored, err := authoritySession(authorityv1.ControlSessionResponse{
		SessionId:   "control_session_0123456789abcdef0123456789abcdef",
		AccessToken: access.String(), AccessExpiresAt: now.Add(time.Hour),
		RefreshToken: refresh.String(), RefreshExpiresAt: now.Add(24 * time.Hour),
	}, "", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if stored.AccessToken != access.String() || stored.RefreshToken != refresh.String() {
		t.Fatalf("stored session = %#v", stored)
	}
}
