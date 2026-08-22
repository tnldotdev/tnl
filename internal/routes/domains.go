package routes

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

var ErrDNSProofPending = errors.New("routes: DNS proof is not ready")

type DomainVerifier interface {
	CheckDomain(context.Context, string, string, bool) error
	IngressAddresses() []string
}

type DNSRecord struct {
	Name  string
	Type  string
	Value string
}

type DomainChallenge struct {
	ID                 string
	PrincipalID        string
	Domain             string
	Token              string
	VerificationTarget string
	Apex               bool
	State              string
	ClaimID            string
	CreatedAt          time.Time
	VerifiedAt         time.Time
	InvalidatedAt      time.Time
	Records            []DNSRecord
}

func (s *Store) CreateDomainChallenge(
	ctx context.Context,
	principalID, domain, requestKey string,
) (DomainChallenge, error) {
	if s.domainVerifier == nil || strings.TrimSpace(principalID) == "" || requestKey == "" ||
		strings.TrimSpace(requestKey) != requestKey || len(requestKey) > 128 {
		return DomainChallenge{}, ErrInvalidArgument
	}
	domain, apex, err := naming.CustomDomain(domain, s.routeSuffix)
	if err != nil {
		return DomainChallenge{}, ErrInvalidArgument
	}
	if apex {
		hasIngress := false
		for _, address := range s.domainVerifier.IngressAddresses() {
			hasIngress = hasIngress || net.ParseIP(address) != nil
		}
		if !hasIngress {
			return DomainChallenge{}, ErrUnavailable
		}
	}
	now := time.Unix(s.now().Unix(), 0).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DomainChallenge{}, fmt.Errorf("routes: begin domain challenge: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	replayed, err := queries.GetDomainChallengeRequest(ctx, statedb.GetDomainChallengeRequestParams{
		PrincipalID: principalID,
		RequestKey:  requestKey,
	})
	if err == nil {
		if replayed.Domain != domain {
			return DomainChallenge{}, ErrInvalidState
		}
		return s.domainChallengeFromDB(replayed), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DomainChallenge{}, fmt.Errorf("routes: read domain challenge request: %w", err)
	}
	count, err := queries.CountDomainChallenges(ctx, principalID)
	if err != nil {
		return DomainChallenge{}, fmt.Errorf("routes: count domain challenges: %w", err)
	}
	if count >= int64(s.maxHostnameClaimRequests) {
		return DomainChallenge{}, ErrInvalidState
	}
	id, err := newID("domain")
	if err != nil {
		return DomainChallenge{}, err
	}
	token, err := newDomainToken()
	if err != nil {
		return DomainChallenge{}, err
	}
	target := token + "." + s.verificationSuffix
	if err := queries.InsertDomainChallenge(ctx, statedb.InsertDomainChallengeParams{
		ID: id, PrincipalID: principalID, RequestKey: requestKey, Domain: domain,
		Token: token, VerificationTarget: target, IsApex: boolInt(apex), CreatedAt: now.Unix(),
	}); err != nil {
		return DomainChallenge{}, fmt.Errorf("routes: insert domain challenge: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return DomainChallenge{}, fmt.Errorf("routes: commit domain challenge: %w", err)
	}
	return s.domainChallengeFromDB(statedb.DomainClaimChallenge{
		ID: id, PrincipalID: principalID, RequestKey: requestKey, Domain: domain,
		Token: token, VerificationTarget: target, IsApex: boolInt(apex),
		State: NameStatePendingDNS, CreatedAt: now.Unix(),
	}), nil
}

func (s *Store) GetDomainChallenge(ctx context.Context, principalID, id string) (DomainChallenge, error) {
	stored, err := s.queries.GetDomainChallenge(ctx, id)
	if errors.Is(err, sql.ErrNoRows) || err == nil && stored.PrincipalID != principalID {
		return DomainChallenge{}, ErrNotFound
	}
	if err != nil {
		return DomainChallenge{}, fmt.Errorf("routes: read domain challenge: %w", err)
	}
	return s.domainChallengeFromDB(stored), nil
}

func (s *Store) VerifyDomainChallenge(
	ctx context.Context,
	principalID, id string,
) (HostnameClaim, error) {
	challenge, err := s.GetDomainChallenge(ctx, principalID, id)
	if err != nil {
		return HostnameClaim{}, err
	}
	if challenge.State == "verified" && challenge.ClaimID != "" {
		claim, err := readClaimByHostname(ctx, s.queries, challenge.Domain)
		return claim, err
	}
	if challenge.State != NameStatePendingDNS {
		return HostnameClaim{}, ErrInvalidState
	}
	if err := s.domainVerifier.CheckDomain(ctx, challenge.Domain, challenge.VerificationTarget, challenge.Apex); err != nil {
		return HostnameClaim{}, fmt.Errorf("%w: %v", ErrDNSProofPending, err)
	}

	now := time.Unix(s.now().Unix(), 0).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: begin domain verification: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	stored, err := queries.GetDomainChallenge(ctx, id)
	if errors.Is(err, sql.ErrNoRows) || err == nil && stored.PrincipalID != principalID {
		return HostnameClaim{}, ErrNotFound
	}
	if err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: reread domain challenge: %w", err)
	}
	if stored.State != NameStatePendingDNS {
		return HostnameClaim{}, ErrInvalidState
	}

	active, err := queries.ListActiveCustomDomainClaims(ctx)
	if err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: list active custom domains: %w", err)
	}
	var existing *statedb.HostnameClaim
	for index := range active {
		candidate := &active[index]
		if candidate.Hostname == stored.Domain {
			existing = candidate
			continue
		}
		if naming.IsWithin(candidate.Hostname, stored.Domain) || naming.IsWithin(stored.Domain, candidate.Hostname) {
			return HostnameClaim{}, ErrNameUnavailable
		}
	}
	if existing == nil {
		candidate, readErr := queries.GetClaimByHostname(ctx, stored.Domain)
		if readErr == nil {
			existing = &candidate
		} else if !errors.Is(readErr, sql.ErrNoRows) {
			return HostnameClaim{}, fmt.Errorf("routes: read released custom domain: %w", readErr)
		}
	}

	var claim HostnameClaim
	switch {
	case existing == nil:
		if err := s.checkActiveClaimQuota(ctx, queries, principalID); err != nil {
			return HostnameClaim{}, err
		}
		claimID, err := newID("claim")
		if err != nil {
			return HostnameClaim{}, err
		}
		if err := queries.InsertCustomDomainClaim(ctx, statedb.InsertCustomDomainClaimParams{
			ID: claimID, PrincipalID: principalID, Hostname: stored.Domain, CreatedAt: now.Unix(),
		}); err != nil {
			return HostnameClaim{}, fmt.Errorf("routes: activate custom domain: %w", err)
		}
		claim = HostnameClaim{
			ID: claimID, PrincipalID: principalID, Hostname: stored.Domain,
			Kind: NameKindPersistentCustom, State: NameStateActive, Source: NameSourceCustom,
			CreatedAt: now, ActivatedAt: now,
		}
	case existing.Kind != NameKindPersistentCustom:
		return HostnameClaim{}, ErrNameUnavailable
	case existing.State == NameStateReleased:
		if err := s.checkActiveClaimQuota(ctx, queries, principalID); err != nil {
			return HostnameClaim{}, err
		}
		count, err := queries.ActivateReleasedCustomDomainClaim(ctx, statedb.ActivateReleasedCustomDomainClaimParams{
			PrincipalID: principalID, ActivatedAt: sql.NullInt64{Int64: now.Unix(), Valid: true}, ID: existing.ID,
		})
		if err != nil || count != 1 {
			return HostnameClaim{}, ErrInvalidState
		}
		claim = hostnameClaimFromDB(*existing)
		claim.PrincipalID, claim.State, claim.ActivatedAt, claim.ReleasedAt = principalID, NameStateActive, now, time.Time{}
	case existing.State == NameStateActive && existing.PrincipalID == principalID:
		claim = hostnameClaimFromDB(*existing)
	case existing.State == NameStateActive:
		return HostnameClaim{}, ErrNameUnavailable
	default:
		return HostnameClaim{}, ErrInvalidState
	}
	verified, err := queries.VerifyDomainChallenge(ctx, statedb.VerifyDomainChallengeParams{
		ClaimID:    sql.NullString{String: claim.ID, Valid: true},
		VerifiedAt: sql.NullInt64{Int64: now.Unix(), Valid: true}, ID: id, PrincipalID: principalID,
	})
	if err != nil || verified != 1 {
		return HostnameClaim{}, ErrInvalidState
	}
	if err := queries.InvalidateOtherDomainChallenges(ctx, statedb.InvalidateOtherDomainChallengesParams{
		InvalidatedAt: sql.NullInt64{Int64: now.Unix(), Valid: true}, Domain: stored.Domain, ID: id,
	}); err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: invalidate old domain challenges: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return HostnameClaim{}, fmt.Errorf("routes: commit domain verification: %w", err)
	}
	return claim, nil
}

func (s *Store) domainChallengeFromDB(stored statedb.DomainClaimChallenge) DomainChallenge {
	result := DomainChallenge{
		ID: stored.ID, PrincipalID: stored.PrincipalID, Domain: stored.Domain,
		Token: stored.Token, VerificationTarget: stored.VerificationTarget,
		Apex: stored.IsApex == 1, State: stored.State, ClaimID: stored.ClaimID.String,
		CreatedAt: time.Unix(stored.CreatedAt, 0).UTC(),
	}
	if stored.VerifiedAt.Valid {
		result.VerifiedAt = time.Unix(stored.VerifiedAt.Int64, 0).UTC()
	}
	if stored.InvalidatedAt.Valid {
		result.InvalidatedAt = time.Unix(stored.InvalidatedAt.Int64, 0).UTC()
	}
	result.Records = s.domainRecords(result.Domain, result.VerificationTarget, result.Apex)
	return result
}

func (s *Store) domainRecords(domain, target string, apex bool) []DNSRecord {
	proof := domain
	if apex {
		proof = "_tnl." + domain
	}
	records := []DNSRecord{{Name: proof + ".", Type: "CNAME", Value: target + "."}}
	if apex {
		addresses := append([]string(nil), s.domainVerifier.IngressAddresses()...)
		sort.Strings(addresses)
		for _, value := range addresses {
			address := net.ParseIP(value)
			if address == nil {
				continue
			}
			typeName := "AAAA"
			if address.To4() != nil {
				typeName = "A"
			}
			records = append(records, DNSRecord{Name: domain + ".", Type: typeName, Value: address.String()})
		}
	}
	return append(records, DNSRecord{Name: "*." + domain + ".", Type: "CNAME", Value: target + "."})
}

func newDomainToken() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("routes: generate domain verification token: %w", err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(material[:])), nil
}

func boolInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
