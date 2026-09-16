package authorityclient

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestValidateIssuedControlSession(t *testing.T) {
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	valid := authorityv1.ControlSessionResponse{
		SessionId:   "control_session_0123456789abcdef0123456789abcdef",
		AccessToken: access.String(), RefreshToken: refresh.String(),
		AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour),
	}
	for _, test := range []struct {
		name           string
		mutate         func(*authorityv1.ControlSessionResponse)
		expectedID     string
		expectedExpiry time.Time
		valid          bool
	}{
		{name: "new session", valid: true},
		{name: "refresh preserves identity and expiry", expectedID: valid.SessionId, expectedExpiry: valid.RefreshExpiresAt, valid: true},
		{name: "same expiry instant in another zone", expectedID: valid.SessionId, expectedExpiry: valid.RefreshExpiresAt.In(time.FixedZone("offset", 3600)), valid: true},
		{name: "equal access and refresh expiry", mutate: func(s *authorityv1.ControlSessionResponse) { s.RefreshExpiresAt = s.AccessExpiresAt }, valid: true},
		{name: "empty access", mutate: func(s *authorityv1.ControlSessionResponse) { s.AccessToken = "" }},
		{name: "malformed access", mutate: func(s *authorityv1.ControlSessionResponse) { s.AccessToken = "access" }},
		{name: "refresh in access field", mutate: func(s *authorityv1.ControlSessionResponse) { s.AccessToken = s.RefreshToken }},
		{name: "access whitespace", mutate: func(s *authorityv1.ControlSessionResponse) { s.AccessToken += " " }},
		{name: "empty refresh", mutate: func(s *authorityv1.ControlSessionResponse) { s.RefreshToken = "" }},
		{name: "malformed refresh", mutate: func(s *authorityv1.ControlSessionResponse) { s.RefreshToken = "refresh" }},
		{name: "access in refresh field", mutate: func(s *authorityv1.ControlSessionResponse) { s.RefreshToken = s.AccessToken }},
		{name: "truncated refresh", mutate: func(s *authorityv1.ControlSessionResponse) { s.RefreshToken = s.RefreshToken[:len(s.RefreshToken)-1] }},
		{name: "empty identity", mutate: func(s *authorityv1.ControlSessionResponse) { s.SessionId = "" }},
		{name: "wrong identity prefix", mutate: func(s *authorityv1.ControlSessionResponse) {
			s.SessionId = "route_session_0123456789abcdef0123456789abcdef"
		}},
		{name: "truncated identity", mutate: func(s *authorityv1.ControlSessionResponse) { s.SessionId = s.SessionId[:len(s.SessionId)-1] }},
		{name: "nonhex identity", mutate: func(s *authorityv1.ControlSessionResponse) {
			s.SessionId = "control_session_" + strings.Repeat("g", 32)
		}},
		{name: "uppercase identity", mutate: func(s *authorityv1.ControlSessionResponse) {
			s.SessionId = "control_session_" + strings.Repeat("A", 32)
		}},
		{name: "identity changed during refresh", expectedID: "control_session_abcdef0123456789abcdef0123456789"},
		{name: "zero access expiry", mutate: func(s *authorityv1.ControlSessionResponse) { s.AccessExpiresAt = time.Time{} }},
		{name: "expired access", mutate: func(s *authorityv1.ControlSessionResponse) { s.AccessExpiresAt = now.Add(-time.Hour) }},
		{name: "zero refresh expiry", mutate: func(s *authorityv1.ControlSessionResponse) { s.RefreshExpiresAt = time.Time{} }},
		{name: "refresh expires before access", mutate: func(s *authorityv1.ControlSessionResponse) {
			s.RefreshExpiresAt = s.AccessExpiresAt.Add(-time.Nanosecond)
		}},
		{name: "refresh expiry extended", expectedExpiry: valid.RefreshExpiresAt.Add(-time.Nanosecond)},
		{name: "refresh expiry shortened", expectedExpiry: valid.RefreshExpiresAt.Add(time.Nanosecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := valid
			if test.mutate != nil {
				test.mutate(&response)
			}
			got, err := ValidateControlSessionResponse(response, test.expectedID, test.expectedExpiry)
			if !test.valid {
				if err == nil || got != (clientstate.ControlSession{}) {
					t.Fatal("invalid response exposed partial session credentials")
				}
				for _, token := range []string{response.AccessToken, response.RefreshToken} {
					if len(token) > 20 && strings.Contains(err.Error(), token) {
						t.Fatal("validation error exposed a credential")
					}
				}
			} else {
				want := clientstate.ControlSession{SessionID: response.SessionId, AccessToken: response.AccessToken, RefreshToken: response.RefreshToken, AccessExpiresAt: response.AccessExpiresAt, RefreshExpiresAt: response.RefreshExpiresAt}
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("valid session fields were not preserved: %v", err)
				}
			}
		})
	}
}
