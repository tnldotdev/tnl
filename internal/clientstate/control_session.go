package clientstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const (
	maxOpaqueTokenBytes = 16 << 10
	maxSessionIDBytes   = 256
)

type ControlSessionKind string

const (
	ControlSessionKindServer                 ControlSessionKind = "server"
	ControlSessionKindAuthorizationAuthority ControlSessionKind = "authorization_authority"
)

type ControlSession struct {
	Kind             ControlSessionKind
	ControlEndpoint  string
	SessionID        string
	Issuer           string
	ClientID         string
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	Grants           []string
	Scopes           []string
}

func (s *Store) ControlSession(ctx context.Context) (ControlSession, bool, error) {
	stored, err := s.database.queries.GetControlSession(ctx, s.controlEndpoint)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlSession{}, false, nil
	}
	if err != nil {
		return ControlSession{}, false, fmt.Errorf("clientstate: read control session: %w", err)
	}
	if stored.SessionID == "" {
		return ControlSession{}, true, errors.New("clientstate: saved control session is invalid")
	}
	accessToken, err := s.secrets.Open(controlSessionContext(stored.SessionID, "access"), stored.AccessToken)
	if err != nil {
		return ControlSession{}, true, err
	}
	refreshToken, err := s.secrets.Open(
		controlSessionContext(stored.SessionID, "refresh"), stored.RefreshToken,
	)
	if err != nil {
		return ControlSession{}, true, err
	}
	var grants, scopes []string
	if err := json.Unmarshal(stored.Grants, &grants); err != nil {
		return ControlSession{}, true, errors.New("clientstate: saved control session grants are invalid")
	}
	if err := json.Unmarshal(stored.Scopes, &scopes); err != nil {
		return ControlSession{}, true, errors.New("clientstate: saved control session scopes are invalid")
	}
	session := ControlSession{
		Kind: ControlSessionKind(stored.Kind), ControlEndpoint: stored.ControlEndpoint, SessionID: stored.SessionID,
		Issuer: stored.Issuer, ClientID: stored.ClientID, AccessToken: string(accessToken),
		AccessExpiresAt: unixNanoTime(stored.AccessExpiresAt), RefreshToken: string(refreshToken),
		RefreshExpiresAt: unixNanoTime(stored.RefreshExpiresAt), Grants: grants, Scopes: scopes,
	}
	if err := s.validateControlSession(session); err != nil {
		return ControlSession{}, true, err
	}
	return session, true, nil
}

func (s *Store) SaveControlSession(ctx context.Context, session ControlSession) error {
	if err := s.validateControlSession(session); err != nil {
		return err
	}
	accessToken, err := s.secrets.Seal(controlSessionContext(session.SessionID, "access"), []byte(session.AccessToken))
	if err != nil {
		return err
	}
	refreshToken, err := s.secrets.Seal(
		controlSessionContext(session.SessionID, "refresh"), []byte(session.RefreshToken),
	)
	if err != nil {
		return err
	}
	grants, err := json.Marshal(session.Grants)
	if err != nil {
		return fmt.Errorf("clientstate: encode control session grants: %w", err)
	}
	scopes, err := json.Marshal(session.Scopes)
	if err != nil {
		return fmt.Errorf("clientstate: encode control session scopes: %w", err)
	}
	if err := s.database.queries.UpsertControlSession(ctx, clientstatedb.UpsertControlSessionParams{
		ServerOrigin: s.controlEndpoint, Kind: string(session.Kind), ControlEndpoint: session.ControlEndpoint,
		SessionID: session.SessionID, Issuer: session.Issuer, ClientID: session.ClientID,
		AccessToken: accessToken, AccessExpiresAt: session.AccessExpiresAt.UTC().UnixNano(),
		RefreshToken: refreshToken, RefreshExpiresAt: timeUnixNano(session.RefreshExpiresAt),
		Grants: grants, Scopes: scopes, UpdatedAt: s.database.now().UTC().UnixNano(),
	}); err != nil {
		return fmt.Errorf("clientstate: save control session: %w", err)
	}
	return nil
}

func (s *Store) validateControlSession(session ControlSession) error {
	endpoint, err := CanonicalServer(session.ControlEndpoint)
	if err != nil || endpoint != session.ControlEndpoint || !validOpaqueValue(session.SessionID, maxSessionIDBytes) ||
		!validIssuer(session.Issuer) || !validOpaqueValue(session.AccessToken, maxOpaqueTokenBytes) ||
		!validOpaqueValue(session.RefreshToken, maxOpaqueTokenBytes) || session.AccessExpiresAt.IsZero() ||
		len(session.ClientID) > 128 || strings.TrimSpace(session.ClientID) != session.ClientID {
		return errors.New("clientstate: invalid control session")
	}
	switch session.Kind {
	case ControlSessionKindServer:
		if endpoint != s.controlEndpoint || session.RefreshExpiresAt.IsZero() ||
			session.AccessExpiresAt.After(session.RefreshExpiresAt) || len(session.Scopes) != 0 ||
			!validControlSessionID(session.SessionID) || !validControlSessionGrants(session.Grants) {
			return errors.New("clientstate: invalid control session")
		}
		if _, _, err := credentials.ParseAccessToken(credentials.AccessToken(session.AccessToken)); err != nil {
			return errors.New("clientstate: invalid control session")
		}
		if _, _, err := credentials.ParseRefreshToken(credentials.RefreshToken(session.RefreshToken)); err != nil {
			return errors.New("clientstate: invalid control session")
		}
	case ControlSessionKindAuthorizationAuthority:
		if session.ClientID == "" || len(session.Grants) != 0 || !validScopes(session.Scopes) ||
			!session.RefreshExpiresAt.IsZero() && session.AccessExpiresAt.After(session.RefreshExpiresAt) {
			return errors.New("clientstate: invalid control session")
		}
	default:
		return errors.New("clientstate: invalid control session")
	}
	return nil
}

func validIssuer(value string) bool {
	if len(value) == 0 || len(value) > 2048 {
		return false
	}
	issuer, err := url.Parse(value)
	return err == nil && issuer.Scheme == "https" && issuer.Host != "" && issuer.User == nil &&
		issuer.RawQuery == "" && issuer.Fragment == ""
}

func validOpaqueValue(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func validScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if !validOpaqueValue(scope, 128) {
			return false
		}
		if _, exists := seen[scope]; exists {
			return false
		}
		seen[scope] = struct{}{}
	}
	return true
}

func validControlSessionID(value string) bool {
	return opaqueid.Valid(value, "control_session_")
}

func validControlSessionGrants(grants []string) bool {
	publish, admin := false, false
	for _, grant := range grants {
		switch grant {
		case "publish":
			if publish {
				return false
			}
			publish = true
		case "admin":
			if admin {
				return false
			}
			admin = true
		default:
			return false
		}
	}
	return publish && (len(grants) == 1 || admin && len(grants) == 2)
}

func (s *Store) RemoveControlSession(ctx context.Context) error {
	if err := s.database.queries.DeleteControlSession(ctx, s.controlEndpoint); err != nil {
		return fmt.Errorf("clientstate: remove control session: %w", err)
	}
	return nil
}

func controlSessionContext(sessionID, credential string) string {
	return "control-session:" + sessionID + ":" + credential
}

func timeUnixNano(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UTC().UnixNano()
}
