package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
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
	SourceIP     string
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
		SourceIP: stored.SourceIp,
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
		DomainID: session.DomainID, Namespace: session.Namespace, SourceIp: session.SourceIP,
		CreatedAt: time.Now().UTC().UnixNano(),
	})
}

func (s *Store) RemoveGuestSession(ctx context.Context) error {
	return s.database.queries.DeleteGuestSession(ctx, s.controlEndpoint)
}

func (s *Store) PreferredGuestNamespace(ctx context.Context) (string, bool, error) {
	namespace, err := s.database.queries.GetPreferredGuestNamespace(ctx, s.controlEndpoint)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	canonical, err := naming.CanonicalizeHostname(namespace)
	if err != nil || canonical != namespace {
		return "", true, errors.New("clientstate: preferred namespace is invalid")
	}
	return namespace, true, nil
}

func (s *Store) SavePreferredGuestNamespace(ctx context.Context, namespace string) error {
	canonical, err := naming.CanonicalizeHostname(namespace)
	if err != nil || canonical != namespace {
		return errors.New("clientstate: preferred namespace is invalid")
	}
	return s.database.queries.SavePreferredGuestNamespace(ctx, clientstatedb.SavePreferredGuestNamespaceParams{
		ServerOrigin: s.controlEndpoint, Namespace: namespace,
	})
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
	ip, err := netip.ParseAddr(session.SourceIP)
	if err != nil || !ip.IsValid() || ip.Zone() != "" {
		return errors.New("clientstate: guest source IP is invalid")
	}
	return nil
}
