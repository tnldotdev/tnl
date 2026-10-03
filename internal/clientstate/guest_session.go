package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type GuestSession struct {
	GuestID      string
	AccessToken  string
	TeamID       string
	MembershipID string
	DomainID     string
	Namespace    string
	ExpiresAt    time.Time
}

func (s *Store) GuestSession(ctx context.Context) (GuestSession, bool, error) {
	stored, err := s.database.queries.GetGuestSession(ctx, s.controlEndpoint)
	if errors.Is(err, sql.ErrNoRows) {
		return GuestSession{}, false, nil
	}
	if err != nil {
		return GuestSession{}, false, fmt.Errorf("clientstate: read guest session: %w", err)
	}
	access, err := s.secrets.Open(ctx, guestSessionContext(stored.GuestID), stored.StoredAccessToken)
	if err != nil {
		return GuestSession{}, true, err
	}
	session := GuestSession{
		GuestID: stored.GuestID, AccessToken: string(access), TeamID: stored.TeamID,
		MembershipID: stored.MembershipID, DomainID: stored.DomainID, Namespace: stored.Namespace,
		ExpiresAt: time.Unix(0, stored.ExpiresAt).UTC(),
	}
	if err := validateGuestSession(session); err != nil {
		return GuestSession{}, true, err
	}
	return session, true, nil
}

func (s *Store) SaveGuestSession(ctx context.Context, session GuestSession) error {
	if err := validateGuestSession(session); err != nil {
		return err
	}
	access, err := s.secrets.Seal(ctx, guestSessionContext(session.GuestID), []byte(session.AccessToken))
	if err != nil {
		return err
	}
	return s.database.queries.SaveGuestSession(ctx, clientstatedb.SaveGuestSessionParams{
		ServerOrigin: s.controlEndpoint, GuestID: session.GuestID, StoredAccessToken: access,
		TeamID: session.TeamID, MembershipID: session.MembershipID,
		DomainID: session.DomainID, Namespace: session.Namespace,
		ExpiresAt: session.ExpiresAt.UnixNano(),
		CreatedAt: time.Now().UTC().UnixNano(),
	})
}

func (s *Store) RemoveGuestSession(ctx context.Context) error {
	return s.database.queries.DeleteGuestSession(ctx, s.controlEndpoint)
}

func guestSessionContext(guestID string) string { return "guest-session:" + guestID + ":access" }

func validateGuestSession(session GuestSession) error {
	if !opaqueid.Valid(session.GuestID, opaqueid.GuestPrefix) ||
		!opaqueid.Valid(session.TeamID, opaqueid.TeamPrefix) ||
		!opaqueid.Valid(session.MembershipID, opaqueid.MembershipPrefix) ||
		!validOpaqueValue(session.DomainID, 256) {
		return errors.New("clientstate: guest session is invalid")
	}
	if _, _, err := credentials.ParseAccessToken(credentials.AccessToken(session.AccessToken)); err != nil {
		return errors.New("clientstate: guest credential is invalid")
	}
	namespace, err := naming.CanonicalizeHostname(session.Namespace)
	if err != nil || namespace != session.Namespace {
		return errors.New("clientstate: guest namespace is invalid")
	}
	if session.ExpiresAt.IsZero() {
		return errors.New("clientstate: guest expiry is invalid")
	}
	return nil
}
