package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

type ControlSession struct {
	AuthorityEndpoint string
	SessionID         string
	AccessToken       string
	AccessExpiresAt   time.Time
	RefreshToken      string
	RefreshExpiresAt  time.Time
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
	session := ControlSession{
		AuthorityEndpoint: stored.AuthorityEndpoint, SessionID: stored.SessionID, AccessToken: string(accessToken),
		AccessExpiresAt: unixNanoTime(stored.AccessExpiresAt), RefreshToken: string(refreshToken),
		RefreshExpiresAt: unixNanoTime(stored.RefreshExpiresAt),
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
	if err := s.database.queries.UpsertControlSession(ctx, clientstatedb.UpsertControlSessionParams{
		ServerOrigin: s.controlEndpoint, AuthorityEndpoint: session.AuthorityEndpoint, SessionID: session.SessionID,
		AccessToken: accessToken, AccessExpiresAt: session.AccessExpiresAt.UTC().UnixNano(),
		RefreshToken: refreshToken, RefreshExpiresAt: timeUnixNano(session.RefreshExpiresAt),
		UpdatedAt: s.database.now().UTC().UnixNano(),
	}); err != nil {
		return fmt.Errorf("clientstate: save control session: %w", err)
	}
	return nil
}

func (s *Store) validateControlSession(session ControlSession) error {
	endpoint, err := CanonicalServer(session.AuthorityEndpoint)
	if err != nil || endpoint != session.AuthorityEndpoint || !validOpaqueValue(session.SessionID, maxSessionIDBytes) ||
		!validOpaqueValue(session.AccessToken, maxOpaqueTokenBytes) ||
		!validOpaqueValue(session.RefreshToken, maxOpaqueTokenBytes) || session.AccessExpiresAt.IsZero() ||
		session.RefreshExpiresAt.IsZero() || session.AccessExpiresAt.After(session.RefreshExpiresAt) ||
		!validControlSessionID(session.SessionID) {
		return errors.New("clientstate: invalid control session")
	}
	if _, _, err := credentials.ParseAccessToken(credentials.AccessToken(session.AccessToken)); err != nil {
		return errors.New("clientstate: invalid control session")
	}
	if _, _, err := credentials.ParseRefreshToken(credentials.RefreshToken(session.RefreshToken)); err != nil {
		return errors.New("clientstate: invalid control session")
	}
	return nil
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

func validControlSessionID(value string) bool {
	return opaqueid.Valid(value, "control_session_")
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
