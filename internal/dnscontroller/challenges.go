package dnscontroller

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

type ChallengeRecord struct {
	ZoneID                string
	ZoneDomain            string
	ClaimedZone           bool
	AuthorityReference    string
	TeamID                string
	DomainID              string
	RecordName            string
	DesiredOwnedValues    []string
	PreviouslyOwnedValues []string
}

type ChallengeStore interface {
	GetDNSAuthority(context.Context, string) (controlstate.DNSAuthority, error)
	GetDNSChallengeContext(context.Context, string, string) (controlstate.DNSChallengeContext, error)
}

type ChallengeProvider interface {
	ReconcileChallenge(context.Context, ChallengeRecord) (Zone, error)
}

type ChallengeVerifier interface {
	VerifyChallenge(context.Context, string, string, []string) (bool, error)
}

type ChallengeManager struct {
	store    ChallengeStore
	provider ChallengeProvider
	verifier ChallengeVerifier
	config   Config
}

func NewChallengeManager(
	store ChallengeStore,
	provider ChallengeProvider,
	verifier ChallengeVerifier,
	config Config,
) (*ChallengeManager, error) {
	if store == nil || provider == nil || verifier == nil || config.ManagedDomain == "" || config.ManagedZoneID == "" {
		return nil, errors.New("dnscontroller: invalid DNS challenge configuration")
	}
	return &ChallengeManager{store: store, provider: provider, verifier: verifier, config: config}, nil
}

func (m *ChallengeManager) Present(ctx context.Context, routeID, authorizationID string) error {
	challenge, record, _, err := m.challengeRecord(ctx, routeID, authorizationID)
	if err != nil {
		return err
	}
	if challenge.State != "presenting" {
		return terminalf("cannot present DNS challenge in state %q", challenge.State)
	}
	_, err = m.provider.ReconcileChallenge(ctx, record)
	return err
}

func (m *ChallengeManager) Verify(ctx context.Context, routeID, authorizationID string) (bool, error) {
	challenge, record, expected, err := m.challengeRecord(ctx, routeID, authorizationID)
	if err != nil {
		return false, err
	}
	if challenge.State != "presented" {
		return false, terminalf("cannot verify DNS challenge in state %q", challenge.State)
	}
	zone, err := m.provider.ReconcileChallenge(ctx, record)
	if err != nil {
		return false, err
	}
	return m.verifier.VerifyChallenge(ctx, record.RecordName, expected, zone.Nameservers)
}

func (m *ChallengeManager) Cleanup(ctx context.Context, routeID, authorizationID string) error {
	challenge, record, _, err := m.challengeRecord(ctx, routeID, authorizationID)
	if err != nil {
		return err
	}
	if challenge.State != "cleaning" {
		return terminalf("cannot clean DNS challenge in state %q", challenge.State)
	}
	_, err = m.provider.ReconcileChallenge(ctx, record)
	return err
}

func (m *ChallengeManager) challengeRecord(
	ctx context.Context,
	routeID, authorizationID string,
) (controlstate.DNSChallengeContext, ChallengeRecord, string, error) {
	challenge, err := m.store.GetDNSChallengeContext(ctx, routeID, authorizationID)
	if err != nil {
		return controlstate.DNSChallengeContext{}, ChallengeRecord{}, "", err
	}
	record := ChallengeRecord{
		ZoneDomain: challenge.CanonicalDomain, TeamID: challenge.TeamID, DomainID: challenge.DomainID,
		RecordName: "_acme-challenge." + strings.TrimPrefix(challenge.Identifier, "*."),
	}
	if challenge.CanonicalDomain == m.config.ManagedDomain {
		record.ZoneID = m.config.ManagedZoneID
	} else {
		if challenge.DNSAuthorityReference == "" {
			return controlstate.DNSChallengeContext{}, ChallengeRecord{}, "", terminalf("DNS challenge has no authority reference")
		}
		authority, err := m.store.GetDNSAuthority(ctx, challenge.DNSAuthorityReference)
		if err != nil {
			return controlstate.DNSChallengeContext{}, ChallengeRecord{}, "", err
		}
		if authority.State != "active" || authority.ProviderZoneID == "" ||
			authority.TeamID != challenge.TeamID || authority.DomainID != challenge.DomainID ||
			authority.CanonicalDomain != challenge.CanonicalDomain {
			return controlstate.DNSChallengeContext{}, ChallengeRecord{}, "", terminalf("DNS challenge authority is not available")
		}
		record.ZoneID, record.ClaimedZone = authority.ProviderZoneID, true
		record.AuthorityReference = authority.Reference
	}
	desired := make(map[string]struct{}, len(challenge.Presentations))
	owned := make(map[string]struct{}, len(challenge.Presentations))
	for _, presentation := range challenge.Presentations {
		value := base64.RawURLEncoding.EncodeToString(presentation.ChallengeDigest[:])
		owned[value] = struct{}{}
		if presentation.Active {
			desired[value] = struct{}{}
		}
	}
	record.DesiredOwnedValues = mapKeys(desired)
	record.PreviouslyOwnedValues = mapKeys(owned)
	expected := base64.RawURLEncoding.EncodeToString(challenge.ChallengeDigest[:])
	return challenge, record, expected, nil
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}
