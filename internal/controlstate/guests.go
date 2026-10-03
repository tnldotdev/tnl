package controlstate

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/ippolicy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const (
	GuestReadyAllowance = 15 * time.Minute
	GuestByteAllowance  = 5 << 20
	GuestLifetime       = 72 * time.Hour
)

var (
	ErrGuestUnknown    = errors.New("controlstate: guest credential is invalid")
	ErrGuestTrialSpent = errors.New("controlstate: guest demo trial is exhausted")
	ErrGuestIssuance   = errors.New("controlstate: guest demo creation is rate limited")
)

type GuestTrial struct {
	ID                    string
	NamespaceLabel        string
	TeamID                string
	MembershipID          string
	DomainID              string
	DNSAuthorityReference string
	SourceIPDigest        string
	SourceIPKeyID         string
	ExpiresAt             time.Time
	UsedReady             time.Duration
	UsedBytes             int64
	LastDemoNumber        int64
}

type NewGuestTrial struct {
	GuestTrial
	Token        credentials.AccessToken
	CredentialID credentials.CredentialID
	Hash         credentials.SecretHash
	SourceIP     netip.Addr
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
	number, err := rand.Int(rand.Reader, big.NewInt(2821109907456)) // 36^8
	if err != nil {
		return NewGuestTrial{}, fmt.Errorf("create guest namespace: %w", err)
	}
	label := strconv.FormatUint(number.Uint64(), 36)
	token, credentialID, hash, err := credentials.NewAccessToken()
	if err != nil {
		return NewGuestTrial{}, err
	}
	return NewGuestTrial{
		GuestTrial: GuestTrial{
			ID: id, NamespaceLabel: "guest-" + strings.Repeat("0", 8-len(label)) + label,
			TeamID: teamID, MembershipID: membershipID,
		},
		Token: token, CredentialID: credentialID, Hash: hash, SourceIP: sourceIP.Unmap(),
	}, nil
}

func (d *Database) CreateGuestTrial(ctx context.Context, guest NewGuestTrial, domainID, dnsAuthorityReference string, now time.Time) (retErr error) {
	if !opaqueid.Valid(guest.ID, opaqueid.GuestPrefix) || !opaqueid.Valid(guest.TeamID, opaqueid.TeamPrefix) ||
		!opaqueid.Valid(guest.MembershipID, opaqueid.MembershipPrefix) || domainID == "" || dnsAuthorityReference == "" {
		return ErrGuestUnknown
	}
	keyID := d.storageKey.CurrentID()
	sourceDigest, err := d.guestIPDigest(keyID, "guest:"+guest.ID, guest.SourceIP)
	if err != nil {
		return err
	}
	issuanceDigest, err := d.guestIPDigest(keyID, "issuance", guest.SourceIP)
	if err != nil {
		return err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "create guest trial", &retErr)()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"tnl:guest-issuance:"+issuanceDigest); err != nil {
		return fmt.Errorf("controlstate: lock guest issuance: %w", err)
	}
	if err := d.guestIssuanceAllowed(ctx, controlstatedb.New(tx), guest.SourceIP, now); err != nil {
		return err
	}
	if _, err := controlstatedb.New(tx).InsertGuestTrial(ctx, controlstatedb.InsertGuestTrialParams{
		ID: guest.ID, CredentialID: text(string(guest.CredentialID)), CredentialHash: guest.Hash[:],
		NamespaceLabel: guest.NamespaceLabel, TeamID: guest.TeamID, MembershipID: guest.MembershipID,
		DomainID: domainID, DnsAuthorityReference: dnsAuthorityReference,
		SourceIpDigest: text(sourceDigest), SourceIpKeyID: text(keyID), IssuanceIpDigest: text(issuanceDigest),
		ExpiresAt: timestamptz(now.Add(GuestLifetime)), CreatedAt: timestamptz(now),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Database) GuestIssuanceAllowed(ctx context.Context, sourceIP netip.Addr, now time.Time) error {
	return d.guestIssuanceAllowed(ctx, controlstatedb.New(d.pool), sourceIP, now)
}

func (d *Database) guestIssuanceAllowed(ctx context.Context, queries *controlstatedb.Queries, sourceIP netip.Addr, now time.Time) error {
	if !sourceIP.IsValid() || sourceIP.Zone() != "" {
		return ErrGuestUnknown
	}
	var count int64
	for _, keyID := range []string{d.storageKey.CurrentID(), d.storageKey.PreviousID()} {
		if keyID == "" {
			continue
		}
		digest, err := d.guestIPDigest(keyID, "issuance", sourceIP.Unmap())
		if err != nil {
			return err
		}
		matched, err := queries.CountRecentGuestTrialsByIP(ctx, controlstatedb.CountRecentGuestTrialsByIPParams{
			SourceIpKeyID: text(keyID), IssuanceIpDigest: text(digest), Since: timestamptz(now.Add(-time.Hour)),
		})
		if err != nil {
			return fmt.Errorf("count recent guest demos: %w", err)
		}
		count += matched
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
	row, err := controlstatedb.New(d.pool).GetGuestTrialByCredentialID(ctx, text(string(credentialID)))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && subtle.ConstantTimeCompare(row.CredentialHash, hash[:]) != 1 {
		return GuestTrial{}, ErrGuestUnknown
	}
	if err != nil {
		return GuestTrial{}, err
	}
	guest := GuestTrial{
		ID: row.ID, NamespaceLabel: row.NamespaceLabel, TeamID: row.TeamID,
		MembershipID: row.MembershipID, DomainID: row.DomainID, DNSAuthorityReference: row.DnsAuthorityReference,
		UsedReady: time.Duration(row.UsedReadyNs), UsedBytes: row.UsedBytes, LastDemoNumber: row.LastDemoNumber,
		ExpiresAt: row.ExpiresAt.Time, SourceIPDigest: row.SourceIpDigest.String, SourceIPKeyID: row.SourceIpKeyID.String,
	}
	return guest, nil
}

func (d *Database) GuestSourceMatches(guest GuestTrial, prefix string) (bool, error) {
	parsed, err := netip.ParsePrefix(prefix)
	if err != nil || parsed.Addr().Zone() != "" || !parsed.IsValid() || parsed.Bits() != parsed.Addr().BitLen() {
		return false, nil
	}
	digest, err := d.guestIPDigest(guest.SourceIPKeyID, "guest:"+guest.ID, parsed.Addr())
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(guest.SourceIPDigest), []byte(digest)) == 1, nil
}

func (d *Database) guestIPDigest(keyID, purpose string, ip netip.Addr) (string, error) {
	if !ip.IsValid() || ip.Zone() != "" {
		return "", ErrGuestUnknown
	}
	key, err := d.storageKey.IPPolicyKey(keyID, purpose)
	if err != nil {
		return "", err
	}
	ip = ip.Unmap()
	entry, err := ippolicy.Hash(key, netip.PrefixFrom(ip, ip.BitLen()))
	if err != nil {
		return "", err
	}
	return entry.Digest, nil
}

func (d *Database) GuestOwnsPublicURL(ctx context.Context, guestID, publicURLID string) (bool, error) {
	return controlstatedb.New(d.pool).GuestOwnsPublicURL(ctx, controlstatedb.GuestOwnsPublicURLParams{
		GuestID: guestID, PublicURLID: publicURLID,
	})
}

func (d *Database) AllocateGuestDemoNumber(ctx context.Context, guestID string, at time.Time) (number int64, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(ctx, tx, "allocate guest demo number", &retErr)()
	queries := controlstatedb.New(tx)
	guest, err := queries.LockGuestTrialByID(ctx, guestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrGuestUnknown
	}
	if err != nil {
		return 0, err
	}
	if !guest.ExpiresAt.Valid || !guest.ExpiresAt.Time.After(at) || guest.UsedBytes >= GuestByteAllowance || guest.UsedReadyNs >= int64(GuestReadyAllowance) {
		return 0, ErrGuestTrialSpent
	}
	count, err := queries.CountGuestCurrentPublicURLs(ctx, guestID)
	if err != nil {
		return 0, err
	}
	if count != 0 || guest.ActivePublishRunID.Valid {
		return 0, ErrPublishRunOpen
	}
	number, err = queries.AdvanceGuestDemoNumber(ctx, controlstatedb.AdvanceGuestDemoNumberParams{
		ID: guestID, AllocatedAt: timestamptz(at),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrGuestTrialSpent
	}
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return number, nil
}
