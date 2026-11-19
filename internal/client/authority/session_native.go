//go:build !js

package authority

import (
	"errors"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

// ValidateControlSessionResponse checks credentials and session data returned by the authority.
func ValidateControlSessionResponse(response authorityv1.ControlSessionResponse, expectedSessionID string, expectedRefreshExpiry time.Time) (clientstate.ControlSession, error) {
	access := credentials.AccessToken(response.AccessToken)
	refresh := credentials.RefreshToken(response.RefreshToken)
	if _, _, err := credentials.ParseAccessToken(access); err != nil {
		return clientstate.ControlSession{}, failure.Wrap("validate authority session", failure.ServerResponseInvalid, errors.New("authorityclient: authority returned an invalid access token"))
	}
	if _, _, err := credentials.ParseRefreshToken(refresh); err != nil {
		return clientstate.ControlSession{}, failure.Wrap("validate authority session", failure.ServerResponseInvalid, errors.New("authorityclient: authority returned an invalid refresh token"))
	}
	if !opaqueid.Valid(response.SessionId, opaqueid.ControlSessionPrefix) || expectedSessionID != "" && response.SessionId != expectedSessionID ||
		!response.AccessExpiresAt.After(time.Now()) || response.RefreshExpiresAt.Before(response.AccessExpiresAt) ||
		!expectedRefreshExpiry.IsZero() && !response.RefreshExpiresAt.Equal(expectedRefreshExpiry) {
		return clientstate.ControlSession{}, failure.Wrap("validate authority session", failure.ServerResponseInvalid, errors.New("authorityclient: authority returned an invalid control session"))
	}
	return clientstate.ControlSession{
		SessionID: response.SessionId, AccessToken: access.String(), AccessExpiresAt: response.AccessExpiresAt,
		RefreshToken: refresh.String(), RefreshExpiresAt: response.RefreshExpiresAt,
	}, nil
}
