package controlstate

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const (
	GuestReadyAllowance = 15 * time.Minute
	GuestByteAllowance  = 5 << 20
	GuestConnections    = 4
)

var (
	ErrGuestUnknown         = errors.New("controlstate: guest credential is invalid")
	ErrGuestTrialSpent      = errors.New("controlstate: guest demo trial is exhausted")
	ErrGuestClaimed         = errors.New("controlstate: guest namespace is already claimed")
	ErrGuestIssuance        = errors.New("controlstate: guest demo creation is rate limited")
	ErrGuestConnectionsFull = errors.New("controlstate: guest demo has four active visitor connections")
)

type GuestTrial struct {
	ID                    string
	NamespaceLabel        string
	TeamID                string
	MembershipID          string
	DomainID              string
	DNSAuthorityReference string
	SourceIP              netip.Addr
	UsedReady             time.Duration
	UsedBytes             int64
	Claimed               bool
}

type NewGuestTrial struct {
	GuestTrial
	Token        credentials.AccessToken
	CredentialID credentials.CredentialID
	Hash         credentials.SecretHash
}

func NewGuestTrialCredential(sourceIP netip.Addr) (NewGuestTrial, error) {
	if !sourceIP.IsValid() || sourceIP.Zone() != "" {
		return NewGuestTrial{}, ErrGuestUnknown
	}
	id, err := opaqueid.New(opaqueid.GuestPrefix)
	if err != nil {
		return NewGuestTrial{}, err
	}
	teamID, err := opaqueid.New(opaqueid.TeamPrefix)
	if err != nil {
		return NewGuestTrial{}, err
	}
	membershipID, err := opaqueid.New(opaqueid.MembershipPrefix)
	if err != nil {
		return NewGuestTrial{}, err
	}
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return NewGuestTrial{}, fmt.Errorf("create guest namespace: %w", err)
	}
	token, credentialID, hash, err := credentials.NewAccessToken()
	if err != nil {
		return NewGuestTrial{}, err
	}
	return NewGuestTrial{
		GuestTrial: GuestTrial{
			ID: id, NamespaceLabel: "guest-" + hex.EncodeToString(bytes),
			TeamID: teamID, MembershipID: membershipID, SourceIP: sourceIP.Unmap(),
		},
		Token: token, CredentialID: credentialID, Hash: hash,
	}, nil
}

func (d *Database) CreateGuestTrial(ctx context.Context, guest NewGuestTrial, domainID, dnsAuthorityReference string, now time.Time) error {
	if !opaqueid.Valid(guest.ID, opaqueid.GuestPrefix) || !opaqueid.Valid(guest.TeamID, opaqueid.TeamPrefix) ||
		!opaqueid.Valid(guest.MembershipID, opaqueid.MembershipPrefix) || domainID == "" || dnsAuthorityReference == "" {
		return ErrGuestUnknown
	}
	if err := d.GuestIssuanceAllowed(ctx, guest.SourceIP, now); err != nil {
		return err
	}
	_, err := controlstatedb.New(d.pool).InsertGuestTrial(ctx, controlstatedb.InsertGuestTrialParams{
		ID: guest.ID, CredentialID: string(guest.CredentialID), CredentialHash: guest.Hash[:],
		NamespaceLabel: guest.NamespaceLabel, TeamID: guest.TeamID, MembershipID: guest.MembershipID,
		DomainID: domainID, DnsAuthorityReference: dnsAuthorityReference,
		SourceIp: guest.SourceIP.String(), CreatedAt: timestamptz(now),
	})
	return err
}

func (d *Database) GuestIssuanceAllowed(ctx context.Context, sourceIP netip.Addr, now time.Time) error {
	if !sourceIP.IsValid() || sourceIP.Zone() != "" {
		return ErrGuestUnknown
	}
	count, err := controlstatedb.New(d.pool).CountRecentGuestTrialsByIP(ctx, controlstatedb.CountRecentGuestTrialsByIPParams{
		SourceIp: sourceIP.Unmap().String(), Since: timestamptz(now.Add(-time.Hour)),
	})
	if err != nil {
		return fmt.Errorf("count recent guest demos: %w", err)
	}
	if count >= 32 {
		return ErrGuestIssuance
	}
	return nil
}

func (d *Database) GuestTrialByAccessToken(ctx context.Context, token credentials.AccessToken) (GuestTrial, error) {
	credentialID, hash, err := credentials.ParseAccessToken(token)
	if err != nil {
		return GuestTrial{}, ErrGuestUnknown
	}
	row, err := controlstatedb.New(d.pool).GetGuestTrialByCredentialID(ctx, string(credentialID))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && subtle.ConstantTimeCompare(row.CredentialHash, hash[:]) != 1 {
		return GuestTrial{}, ErrGuestUnknown
	}
	if err != nil {
		return GuestTrial{}, err
	}
	guest := GuestTrial{
		ID: row.ID, NamespaceLabel: row.NamespaceLabel, TeamID: row.TeamID,
		MembershipID: row.MembershipID, DomainID: row.DomainID, DNSAuthorityReference: row.DnsAuthorityReference,
		UsedReady: time.Duration(row.UsedReadyNs), UsedBytes: row.UsedBytes, Claimed: row.ClaimedAt.Valid,
	}
	guest.SourceIP, err = netip.ParseAddr(row.SourceIp)
	if err != nil {
		return GuestTrial{}, ErrGuestUnknown
	}
	return guest, nil
}

func (d *Database) GuestOwnsPublicURL(ctx context.Context, guestID, publicURLID string) (bool, error) {
	return controlstatedb.New(d.pool).GuestOwnsPublicURL(ctx, controlstatedb.GuestOwnsPublicURLParams{
		GuestID: guestID, PublicURLID: publicURLID,
	})
}

func (d *Database) ClaimGuestTrial(ctx context.Context, guestID string, at time.Time) error {
	count, err := controlstatedb.New(d.pool).MarkGuestTrialClaimed(ctx, controlstatedb.MarkGuestTrialClaimedParams{
		ID: guestID, ClaimedAt: timestamptz(at),
	})
	if err != nil {
		return err
	}
	if count == 0 {
		stored, err := controlstatedb.New(d.pool).GetGuestTrialByID(ctx, guestID)
		if err == nil && stored.ClaimedAt.Valid {
			return nil
		}
		return ErrGuestUnknown
	}
	return nil
}

func (d *Database) ReserveGuestVisitor(
	ctx context.Context, ingress IngressLeaseIdentity, publicURLID, visitorID string, at time.Time,
) (expiresAt time.Time, retErr error) {
	if !opaqueid.Valid(visitorID, opaqueid.VisitorConnectionPrefix) || !validStateText(publicURLID) {
		return time.Time{}, ErrGuestUnknown
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer rollback(ctx, tx, "reserve guest visitor", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := lockCurrentIngressLease(ctx, queries, ingress, at); err != nil {
		return time.Time{}, err
	}
	guest, err := queries.LockGuestForVisitor(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrGuestUnknown
	}
	if err != nil {
		return time.Time{}, err
	}
	if guest.ClaimedAt.Valid || !guest.ActivePublishRunID.Valid || !guest.ActiveReadyAt.Valid ||
		guest.UsedBytes >= GuestByteAllowance ||
		guest.UsedReadyNs+at.Sub(guest.ActiveReadyAt.Time).Nanoseconds() >= int64(GuestReadyAllowance) {
		return time.Time{}, ErrGuestTrialSpent
	}
	if err := queries.DeleteExpiredGuestVisitorSlots(ctx, timestamptz(at)); err != nil {
		return time.Time{}, err
	}
	_, err = queries.GetGuestVisitorSlot(ctx, visitorID)
	if errors.Is(err, pgx.ErrNoRows) {
		count, err := queries.CountActiveGuestVisitorSlots(ctx, controlstatedb.CountActiveGuestVisitorSlotsParams{
			GuestID: guest.ID, Now: timestamptz(at),
		})
		if err != nil {
			return time.Time{}, err
		}
		if count >= GuestConnections {
			return time.Time{}, ErrGuestConnectionsFull
		}
	} else if err != nil {
		return time.Time{}, err
	}
	expiresAt = at.Add(30 * time.Second)
	trialDeadline := guest.ActiveReadyAt.Time.Add(GuestReadyAllowance - time.Duration(guest.UsedReadyNs))
	if trialDeadline.Before(expiresAt) {
		expiresAt = trialDeadline
	}
	updated, err := queries.UpsertGuestVisitorSlot(ctx, controlstatedb.UpsertGuestVisitorSlotParams{
		VisitorConnectionID: visitorID, GuestID: guest.ID, IngressID: ingress.IngressID,
		ExpiresAt: timestamptz(expiresAt),
	})
	if err != nil || updated != 1 {
		return time.Time{}, ErrGuestUnknown
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}

func (d *Database) ReleaseGuestVisitor(ctx context.Context, visitorID, ingressID string) error {
	if !opaqueid.Valid(visitorID, opaqueid.VisitorConnectionPrefix) || !validStateText(ingressID) {
		return ErrGuestUnknown
	}
	_, err := controlstatedb.New(d.pool).ReleaseGuestVisitorSlot(ctx, controlstatedb.ReleaseGuestVisitorSlotParams{
		VisitorConnectionID: visitorID, IngressID: ingressID,
	})
	return err
}
