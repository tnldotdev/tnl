package clientstate

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
)

const (
	controlSessionSchemaVersion = 2
	maxOpaqueTokenBytes         = 16 << 10
	maxSessionIDBytes           = 256
)

type ControlSessionKind string

const (
	ControlSessionKindCore                   ControlSessionKind = "core"
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

type controlSessionFile struct {
	SchemaVersion    int                `json:"schema_version"`
	Kind             ControlSessionKind `json:"kind"`
	ControlEndpoint  string             `json:"control_endpoint"`
	SessionID        string             `json:"session_id"`
	Issuer           string             `json:"issuer"`
	ClientID         string             `json:"client_id,omitempty"`
	AccessToken      []byte             `json:"access_token"`
	AccessExpiresAt  time.Time          `json:"access_expires_at"`
	RefreshToken     []byte             `json:"refresh_token"`
	RefreshExpiresAt time.Time          `json:"refresh_expires_at"`
	Grants           []string           `json:"grants,omitempty"`
	Scopes           []string           `json:"scopes,omitempty"`
}

func (s *Store) ControlSession() (ControlSession, bool, error) {
	var stored controlSessionFile
	found, err := readJSON(s.controlSessionPath, &stored)
	if err != nil || !found {
		return ControlSession{}, found, err
	}
	if stored.SchemaVersion != controlSessionSchemaVersion || stored.SessionID == "" {
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
	session := ControlSession{
		Kind: stored.Kind, ControlEndpoint: stored.ControlEndpoint, SessionID: stored.SessionID,
		Issuer: stored.Issuer, ClientID: stored.ClientID, AccessToken: string(accessToken),
		AccessExpiresAt: stored.AccessExpiresAt, RefreshToken: string(refreshToken),
		RefreshExpiresAt: stored.RefreshExpiresAt, Grants: append([]string(nil), stored.Grants...),
		Scopes: append([]string(nil), stored.Scopes...),
	}
	if err := s.validateControlSession(session); err != nil {
		return ControlSession{}, true, err
	}
	return session, true, nil
}

func (s *Store) SaveControlSession(session ControlSession) error {
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
	return writeJSON(s.controlSessionPath, controlSessionFile{
		SchemaVersion: controlSessionSchemaVersion, Kind: session.Kind, ControlEndpoint: session.ControlEndpoint,
		SessionID: session.SessionID, Issuer: session.Issuer, ClientID: session.ClientID,
		AccessToken: accessToken, AccessExpiresAt: session.AccessExpiresAt.UTC(),
		RefreshToken: refreshToken, RefreshExpiresAt: session.RefreshExpiresAt.UTC(),
		Grants: append([]string(nil), session.Grants...), Scopes: append([]string(nil), session.Scopes...),
	})
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
	case ControlSessionKindCore:
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
	const prefix = "control_session_"
	if len(value) != len(prefix)+32 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
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

func (s *Store) RemoveControlSession() error {
	if err := os.Remove(s.controlSessionPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.serverDir)
}

func controlSessionContext(sessionID, credential string) string {
	return "control-session:" + sessionID + ":" + credential
}
