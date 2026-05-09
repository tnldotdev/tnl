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

type DomainVerification struct {
	ID                 string
	IdentityID         string
	Domain             string
	Token              string
	VerificationTarget string
	Apex               bool
	Status             string
	HostnameID         string
	CreatedAt          time.Time
	VerifiedAt         time.Time
	InvalidatedAt      time.Time
	Records            []DNSRecord
}

const (
	DomainVerificationStatusPending     = "pending"
	DomainVerificationStatusVerified    = "verified"
	DomainVerificationStatusInvalidated = "invalidated"
)

func (s *Store) CreateDomainVerification(
	ctx context.Context,
	identityID, domain, requestKey string,
) (DomainVerification, error) {
	if s.domainVerifier == nil || strings.TrimSpace(identityID) == "" || requestKey == "" ||
		strings.TrimSpace(requestKey) != requestKey || len(requestKey) > 128 {
		return DomainVerification{}, ErrInvalidArgument
	}
	domain, apex, err := naming.CustomDomain(domain, s.hostnameSuffix)
	if err != nil {
		return DomainVerification{}, ErrInvalidArgument
	}
	if apex {
		hasIngress := false
		for _, address := range s.domainVerifier.IngressAddresses() {
			hasIngress = hasIngress || net.ParseIP(address) != nil
		}
		if !hasIngress {
			return DomainVerification{}, ErrUnavailable
		}
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DomainVerification{}, fmt.Errorf("routes: begin domain verification: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	replayed, err := queries.GetDomainVerificationRequest(ctx, statedb.GetDomainVerificationRequestParams{
		IdentityID: identityID,
		RequestKey: requestKey,
	})
	if err == nil {
		if replayed.Domain != domain {
			return DomainVerification{}, ErrInvalidStatus
		}
		return s.domainVerificationFromDB(replayed), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DomainVerification{}, fmt.Errorf("routes: read domain verification request: %w", err)
	}
	count, err := queries.CountDomainVerifications(ctx, identityID)
	if err != nil {
		return DomainVerification{}, fmt.Errorf("routes: count domain verifications: %w", err)
	}
	if count >= int64(s.maxHostnameRequests) {
		return DomainVerification{}, ErrInvalidStatus
	}
	id, err := newID("verification")
	if err != nil {
		return DomainVerification{}, err
	}
	token, err := newDomainToken()
	if err != nil {
		return DomainVerification{}, err
	}
	target := token + "." + s.verificationSuffix
	if err := queries.InsertDomainVerification(ctx, statedb.InsertDomainVerificationParams{
		ID: id, IdentityID: identityID, RequestKey: requestKey, Domain: domain,
		Token: token, VerificationTarget: target, IsApex: boolInt(apex), CreatedAt: now.UnixNano(),
	}); err != nil {
		return DomainVerification{}, fmt.Errorf("routes: insert domain verification: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return DomainVerification{}, fmt.Errorf("routes: commit domain verification: %w", err)
	}
	return s.domainVerificationFromDB(statedb.DomainVerification{
		ID: id, IdentityID: identityID, RequestKey: requestKey, Domain: domain,
		Token: token, VerificationTarget: target, IsApex: boolInt(apex),
		Status: DomainVerificationStatusPending, CreatedAt: now.UnixNano(),
	}), nil
}

func (s *Store) GetDomainVerification(ctx context.Context, identityID, id string) (DomainVerification, error) {
	stored, err := s.queries.GetDomainVerification(ctx, id)
	if errors.Is(err, sql.ErrNoRows) || err == nil && stored.IdentityID != identityID {
		return DomainVerification{}, ErrNotFound
	}
	if err != nil {
		return DomainVerification{}, fmt.Errorf("routes: read domain verification: %w", err)
	}
	return s.domainVerificationFromDB(stored), nil
}

func (s *Store) CompleteDomainVerification(
	ctx context.Context,
	identityID, id string,
) (Hostname, error) {
	verification, err := s.GetDomainVerification(ctx, identityID, id)
	if err != nil {
		return Hostname{}, err
	}
	if verification.Status == "verified" && verification.HostnameID != "" {
		hostname, err := readHostnameByName(ctx, s.queries, verification.Domain)
		return hostname, err
	}
	if verification.Status != DomainVerificationStatusPending {
		return Hostname{}, ErrInvalidStatus
	}
	if err := s.domainVerifier.CheckDomain(ctx, verification.Domain, verification.VerificationTarget, verification.Apex); err != nil {
		return Hostname{}, fmt.Errorf("%w: %v", ErrDNSProofPending, err)
	}

	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Hostname{}, fmt.Errorf("routes: begin domain verification: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	stored, err := queries.GetDomainVerification(ctx, id)
	if errors.Is(err, sql.ErrNoRows) || err == nil && stored.IdentityID != identityID {
		return Hostname{}, ErrNotFound
	}
	if err != nil {
		return Hostname{}, fmt.Errorf("routes: reread domain verification: %w", err)
	}
	if stored.Status != DomainVerificationStatusPending {
		return Hostname{}, ErrInvalidStatus
	}

	active, err := queries.ListActiveCustomDomainHostnames(ctx)
	if err != nil {
		return Hostname{}, fmt.Errorf("routes: list active custom domains: %w", err)
	}
	var existing *statedb.Hostname
	for index := range active {
		candidate := &active[index]
		if candidate.Hostname == stored.Domain {
			existing = candidate
			continue
		}
		if naming.IsWithin(candidate.Hostname, stored.Domain) || naming.IsWithin(stored.Domain, candidate.Hostname) {
			return Hostname{}, ErrNameUnavailable
		}
	}
	if existing == nil {
		candidate, readErr := queries.GetHostnameByHostname(ctx, stored.Domain)
		if readErr == nil {
			existing = &candidate
		} else if !errors.Is(readErr, sql.ErrNoRows) {
			return Hostname{}, fmt.Errorf("routes: read available custom domain: %w", readErr)
		}
	}

	var hostname Hostname
	switch {
	case existing == nil:
		if err := s.checkActiveHostnameQuota(ctx, queries, identityID); err != nil {
			return Hostname{}, err
		}
		hostnameID, err := newID("hostname")
		if err != nil {
			return Hostname{}, err
		}
		if err := queries.InsertCustomDomainHostname(ctx, statedb.InsertCustomDomainHostnameParams{
			ID: hostnameID, IdentityID: identityID, Hostname: stored.Domain, CreatedAt: now.UnixNano(),
		}); err != nil {
			return Hostname{}, fmt.Errorf("routes: activate custom domain: %w", err)
		}
		hostname = Hostname{
			ID: hostnameID, IdentityID: identityID, Hostname: stored.Domain,
			Kind: HostnameKindCustomDomain, Status: HostnameStatusActive, Source: HostnameSourceUser,
			CreatedAt: now, ActivatedAt: now,
		}
	case existing.Kind != HostnameKindCustomDomain:
		return Hostname{}, ErrNameUnavailable
	case existing.Status == HostnameStatusAvailable:
		if err := s.checkActiveHostnameQuota(ctx, queries, identityID); err != nil {
			return Hostname{}, err
		}
		count, err := queries.ActivateAvailableCustomDomainHostname(ctx, statedb.ActivateAvailableCustomDomainHostnameParams{
			IdentityID: identityID, ActivatedAt: sql.NullInt64{Int64: now.UnixNano(), Valid: true}, ID: existing.ID,
		})
		if err != nil || count != 1 {
			return Hostname{}, ErrInvalidStatus
		}
		hostname = hostnameFromDB(*existing)
		hostname.IdentityID, hostname.Status, hostname.ActivatedAt, hostname.DeactivatedAt = identityID, HostnameStatusActive, now, time.Time{}
	case existing.Status == HostnameStatusActive && existing.IdentityID.String == identityID:
		hostname = hostnameFromDB(*existing)
	case existing.Status == HostnameStatusActive:
		return Hostname{}, ErrNameUnavailable
	default:
		return Hostname{}, ErrInvalidStatus
	}
	verified, err := queries.CompleteDomainVerification(ctx, statedb.CompleteDomainVerificationParams{
		HostnameID: sql.NullString{String: hostname.ID, Valid: true},
		VerifiedAt: sql.NullInt64{Int64: now.UnixNano(), Valid: true}, ID: id, IdentityID: identityID,
	})
	if err != nil || verified != 1 {
		return Hostname{}, ErrInvalidStatus
	}
	if err := queries.InvalidateOtherDomainVerifications(ctx, statedb.InvalidateOtherDomainVerificationsParams{
		InvalidatedAt: sql.NullInt64{Int64: now.UnixNano(), Valid: true}, Domain: stored.Domain, ID: id,
	}); err != nil {
		return Hostname{}, fmt.Errorf("routes: invalidate old domain verifications: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Hostname{}, fmt.Errorf("routes: commit domain verification: %w", err)
	}
	return hostname, nil
}

func (s *Store) domainVerificationFromDB(stored statedb.DomainVerification) DomainVerification {
	result := DomainVerification{
		ID: stored.ID, IdentityID: stored.IdentityID, Domain: stored.Domain,
		Token: stored.Token, VerificationTarget: stored.VerificationTarget,
		Apex: stored.IsApex == 1, Status: stored.Status, HostnameID: stored.HostnameID.String,
		CreatedAt: time.Unix(0, stored.CreatedAt).UTC(),
	}
	if stored.VerifiedAt.Valid {
		result.VerifiedAt = time.Unix(0, stored.VerifiedAt.Int64).UTC()
	}
	if stored.InvalidatedAt.Valid {
		result.InvalidatedAt = time.Unix(0, stored.InvalidatedAt.Int64).UTC()
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
