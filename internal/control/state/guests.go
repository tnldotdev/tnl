package state

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
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

const (
	GuestReadyAllowance = 20 * time.Minute
	GuestLifetime       = 72 * time.Hour
)

var (
	ErrGuestUnknown    = errors.New("controlstate: guest credential is invalid")
	ErrGuestTrialSpent = errors.New("controlstate: guest demo trial is exhausted")
	ErrGuestIssuance   = errors.New("controlstate: guest demo creation is rate limited")
	ErrGuestNamespace  = errors.New("controlstate: guest namespace is reserved")
)

type GuestTrial struct {
	ID                    string
	NamespaceLabel        string
	DomainID              string
	IngressPoolID         string
	DNSAuthorityReference string
	SourceIPDigest        string
	SourceIPKeyID         string
	ExpiresAt             time.Time
	UsedReady             time.Duration
	ReadyDeadline         time.Time
	ServingUntil          time.Time
	LastDemoNumber        int64
}

// GuestCredential contains the trial bearer and the server-observed request
// peer. it is not a publisher grant, share, control session, or caller identity.
type GuestCredential struct {
	Token    credentials.AccessToken
	SourceIP netip.Addr
}

type NewGuestTrial struct {
	GuestTrial
	Token        credentials.AccessToken
	CredentialID credentials.CredentialID
	Hash         credentials.SecretHash
	SourceIP     netip.Addr
}

func NewGuestTrialCredential(sourceIP netip.Addr) (NewGuestTrial, error) {
	if !sourceIP.IsValid() || sourceIP.Zone() != "" || sourceIP.Unmap().IsUnspecified() {
		return NewGuestTrial{}, ErrGuestUnknown
	}
	id, err := opaqueid.New(opaqueid.GuestPrefix)
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
		},
		Token: token, CredentialID: credentialID, Hash: hash, SourceIP: sourceIP.Unmap(),
	}, nil
}

// CreateGuestTrial provisions the managed domain and reserves the label.
// the reservation and trial commit together before a signed-in user can claim it.
func (d *Database) CreateGuestTrial(ctx context.Context, guest NewGuestTrial, managedDomain string, now time.Time) (result GuestTrial, retErr error) {
	clock := newAuthorizationClock(now)
	credentialID, hash, err := credentials.ParseAccessToken(guest.Token)
	if err != nil || credentialID != guest.CredentialID || subtle.ConstantTimeCompare(hash[:], guest.Hash[:]) != 1 ||
		!opaqueid.Valid(guest.ID, opaqueid.GuestPrefix) || !validStateText(managedDomain) || now.IsZero() {
		return result, ErrGuestUnknown
	}
	if err := d.requireOpen(); err != nil {
		return result, err
	}
	keyID := d.storageKey.CurrentID()
	sourceDigest, err := d.guestIPDigest(keyID, "guest:"+guest.ID, guest.SourceIP)
	if err != nil {
		return result, err
	}
	issuanceDigest, err := d.guestIPDigest(keyID, "issuance", guest.SourceIP)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create guest trial", &retErr)()
	queries := controlstatedb.New(tx)
	if err := queries.LockIdentityBootstrap(ctx); err != nil {
		return result, err
	}
	domain, err := ensureManagedDomain(ctx, queries, managedDomain, now)
	if err != nil {
		return result, err
	}
	if _, err := queries.ReserveManagedLabel(ctx, controlstatedb.ReserveManagedLabelParams{Label: guest.NamespaceLabel, CreatedAt: timestamp(now)}); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrGuestNamespace
	} else if err != nil {
		return result, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"tnl:guest-issuance:"+issuanceDigest); err != nil {
		return result, fmt.Errorf("controlstate: lock guest issuance: %w", err)
	}
	pool, err := queries.GetIngressPool(ctx, PrimaryIngressPoolID)
	if err != nil {
		return result, err
	}
	if pool.State != string(IngressPoolEnabled) {
		return result, ErrServiceAccess
	}
	createdAt := clock.current()
	if err := d.guestIssuanceAllowed(ctx, queries, guest.SourceIP, createdAt); err != nil {
		return result, err
	}
	row, err := queries.InsertGuestTrial(ctx, controlstatedb.InsertGuestTrialParams{
		ID: guest.ID, CredentialID: text(string(guest.CredentialID)), CredentialHash: guest.Hash[:],
		NamespaceLabel: guest.NamespaceLabel, DomainID: domain.ID, IngressPoolID: pool.ID,
		DnsAuthorityReference: domain.DnsAuthorityReference.String,
		SourceIpDigest:        text(sourceDigest), SourceIpKeyID: text(keyID), IssuanceIpDigest: text(issuanceDigest),
		ExpiresAt: timestamptz(createdAt.Add(GuestLifetime)), CreatedAt: timestamptz(createdAt),
	})
	if err != nil {
		return result, err
	}
	return guestTrialRecord(row), tx.Commit(ctx)
}

func (d *Database) GuestIssuanceAllowed(ctx context.Context, sourceIP netip.Addr, now time.Time) error {
	return d.guestIssuanceAllowed(ctx, controlstatedb.New(d.pool), sourceIP, now)
}

func (d *Database) guestIssuanceAllowed(ctx context.Context, queries *controlstatedb.Queries, sourceIP netip.Addr, now time.Time) error {
	if !sourceIP.IsValid() || sourceIP.Zone() != "" || sourceIP.Unmap().IsUnspecified() {
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
	return guestTrialRecord(row), nil
}

func guestTrialRecord(row controlstatedb.ControlGuestTrial) GuestTrial {
	return GuestTrial{
		ID: row.ID, NamespaceLabel: row.NamespaceLabel,
		DomainID: row.DomainID, IngressPoolID: row.IngressPoolID, DNSAuthorityReference: row.DnsAuthorityReference,
		UsedReady: time.Duration(row.UsedReadyNs), LastDemoNumber: row.LastDemoNumber,
		ExpiresAt: row.ExpiresAt.Time, SourceIPDigest: row.SourceIpDigest.String, SourceIPKeyID: row.SourceIpKeyID.String,
		ReadyDeadline: row.ReadyDeadline.Time, ServingUntil: row.ServingUntil.Time,
	}
}

// lockGuestCredential repeats bearer and source checks under the trial lock.
// callers acquire service, run, and publisher locks only after this succeeds.
func (d *Database) lockGuestCredential(ctx context.Context, q *controlstatedb.Queries, credential GuestCredential, clock authorizationClock) (controlstatedb.ControlGuestTrial, error) {
	id, hash, err := credentials.ParseAccessToken(credential.Token)
	if err != nil || !credential.SourceIP.IsValid() || credential.SourceIP.Zone() != "" || credential.SourceIP.Unmap().IsUnspecified() {
		return controlstatedb.ControlGuestTrial{}, ErrGuestUnknown
	}
	snapshot, err := q.GetGuestTrialByCredentialID(ctx, text(string(id)))
	if err != nil {
		return controlstatedb.ControlGuestTrial{}, publisherLookupError(err, ErrGuestUnknown)
	}
	trial, err := q.LockGuestTrialByID(ctx, snapshot.ID)
	if err != nil {
		return trial, publisherLookupError(err, ErrGuestUnknown)
	}
	if trial.CredentialID.String != string(id) || subtle.ConstantTimeCompare(trial.CredentialHash, hash[:]) != 1 {
		return trial, ErrGuestUnknown
	}
	if !trial.ExpiresAt.Time.After(clock.current()) {
		return trial, ErrGuestTrialSpent
	}
	prefix := netip.PrefixFrom(credential.SourceIP.Unmap(), credential.SourceIP.Unmap().BitLen()).String()
	match, err := d.GuestSourceMatches(guestTrialRecord(trial), prefix)
	if err != nil {
		return trial, err
	}
	if !match {
		return trial, authorization.ErrGuestIPChanged
	}
	return trial, nil
}

func guestPublicationEligible(trial controlstatedb.ControlGuestTrial, now time.Time) bool {
	return trial.ExpiresAt.Valid && trial.ExpiresAt.Time.After(now) && !trial.EndedAt.Valid &&
		trial.UsedReadyNs < int64(GuestReadyAllowance) && (!trial.ReadyDeadline.Valid || trial.ReadyDeadline.Time.After(now))
}

func (d *Database) GuestSourceMatches(guest GuestTrial, prefix string) (bool, error) {
	parsed, err := netip.ParsePrefix(prefix)
	if err != nil || parsed.Addr().Zone() != "" || !parsed.IsValid() || parsed.Addr().Unmap().IsUnspecified() || parsed.Bits() != parsed.Addr().BitLen() {
		return false, nil
	}
	digest, err := d.guestIPDigest(guest.SourceIPKeyID, "guest:"+guest.ID, parsed.Addr())
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(guest.SourceIPDigest), []byte(digest)) == 1, nil
}

func (d *Database) guestIPDigest(keyID, purpose string, ip netip.Addr) (string, error) {
	if !ip.IsValid() || ip.Zone() != "" || ip.Unmap().IsUnspecified() {
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

// callers hold the trial, service and run locks through commit. no authority is
// returned until its ready horizon and the bounded publisher lease commit too.
func boundGuestServingAuthority(ctx context.Context, queries *controlstatedb.Queries, run controlstatedb.ControlServiceRun, now time.Time) (controlstatedb.ControlServiceRun, error) {
	if !run.GuestID.Valid {
		return run, nil
	}
	deadline, err := queries.UpdateGuestServingAuthority(ctx, controlstatedb.UpdateGuestServingAuthorityParams{
		ServiceRunID: run.ID, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrGuestTrialSpent
	}
	if err != nil {
		return run, fmt.Errorf("record guest serving authority: %w", err)
	}
	if !deadline.Valid || !deadline.Time.After(now) {
		return run, ErrGuestTrialSpent
	}
	return queries.LimitGuestServiceRunExpiry(ctx, controlstatedb.LimitGuestServiceRunExpiryParams{
		ServiceRunID: run.ID, Deadline: deadline,
	})
}

// the ordinary READY transition owns first readiness. retries and demotion never
// restart the trial clock; the existing settlement math is shared by all closes.
func markGuestServiceRunReady(ctx context.Context, q *controlstatedb.Queries, run controlstatedb.ControlServiceRun, now time.Time) (controlstatedb.ControlServiceRun, error) {
	if !run.GuestID.Valid {
		return run, nil
	}
	if !run.ReadyAt.Valid || run.State != "ready" {
		return run, ErrServiceAccess
	}
	if _, err := q.MarkGuestRunReady(ctx, controlstatedb.MarkGuestRunReadyParams{
		ServiceRunID: text(run.ID), ReadyAt: run.ReadyAt,
	}); err != nil {
		return run, err
	}
	trial, err := q.GetGuestTrialByID(ctx, run.GuestID.String)
	if err != nil {
		return run, err
	}
	if trial.ActiveServiceRunID.String != run.ID || !trial.ActiveReadyAt.Valid || !guestPublicationEligible(trial, now) {
		return run, ErrGuestTrialSpent
	}
	return boundGuestServingAuthority(ctx, q, run, now)
}
