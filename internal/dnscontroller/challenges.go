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
	WithDNSChallengeLock(context.Context, string, func() error) error
}

var ErrChallengesNotConfigured = terminalf("DNS challenge automation is not configured")

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
	_, err := m.reconcile(ctx, routeID, authorizationID, "presenting")
	return err
}

func (m *ChallengeManager) Verify(ctx context.Context, routeID, authorizationID string) (bool, error) {
	return m.reconcile(ctx, routeID, authorizationID, "presented")
}

func (m *ChallengeManager) Cleanup(ctx context.Context, routeID, authorizationID string) error {
	_, err := m.reconcile(ctx, routeID, authorizationID, "cleaning")
	return err
}

func (m *ChallengeManager) reconcile(ctx context.Context, routeID, authorizationID, state string) (bool, error) {
	initial, err := m.store.GetDNSChallengeContext(ctx, routeID, authorizationID)
	if err != nil {
		return false, err
	}
	recordName := "_acme-challenge." + strings.TrimPrefix(initial.Identifier, "*.")
	verified := false
	err = m.store.WithDNSChallengeLock(ctx, recordName, func() error {
		challenge, record, expected, err := m.challengeRecord(ctx, routeID, authorizationID)
		if err != nil {
			return err
		}
		if challenge.State != state || record.RecordName != recordName {
			return terminalf("cannot reconcile DNS challenge in state %q for %q", challenge.State, record.RecordName)
		}
		zone, err := m.provider.ReconcileChallenge(ctx, record)
		if err == nil && state == "presented" {
			verified, err = m.verifier.VerifyChallenge(ctx, record.RecordName, expected, zone.Nameservers)
		}
		return err
	})
	return verified, err
}

func (m *ChallengeManager) challengeRecord(
	ctx context.Context,
	routeID, authorizationID string,
) (controlstate.DNSChallengeContext, ChallengeRecord, string, error) {
	challenge, err := m.store.GetDNSChallengeContext(ctx, routeID, authorizationID)
	if err != nil {
		return controlstate.DNSChallengeContext{}, ChallengeRecord{}, "", err
	}
	baseIdentifier := strings.TrimPrefix(challenge.Identifier, "*.")
	record := ChallengeRecord{
		ZoneDomain: challenge.CanonicalDomain, TeamID: challenge.TeamID, DomainID: challenge.DomainID,
		RecordName: "_acme-challenge." + baseIdentifier,
	}
	if (challenge.CanonicalDomain == "" || challenge.CanonicalDomain == m.config.ManagedDomain) &&
		(baseIdentifier == m.config.ManagedDomain || strings.HasSuffix(baseIdentifier, "."+m.config.ManagedDomain)) {
		record.ZoneID, record.ZoneDomain = m.config.ManagedZoneID, m.config.ManagedDomain
	} else {
		authority, err := m.store.GetDNSAuthority(ctx, challenge.DNSAuthorityReference)
		if errors.Is(err, controlstate.ErrDNSAuthorityInvalid) || errors.Is(err, controlstate.ErrDNSAuthorityNotFound) {
			return controlstate.DNSChallengeContext{}, ChallengeRecord{}, "", terminalf("DNS challenge authority is not available")
		}
		if err != nil {
			return controlstate.DNSChallengeContext{}, ChallengeRecord{}, "", err
		}
		if authority.State != "ready" && !(authority.State == "releasing" && challenge.State == "cleaning") || authority.ProviderZoneID == "" ||
			authority.Reference != challenge.DNSAuthorityReference ||
			authority.TeamID != challenge.TeamID || authority.DomainID != challenge.DomainID ||
			authority.CanonicalDomain != challenge.CanonicalDomain ||
			baseIdentifier != authority.CanonicalDomain && !strings.HasSuffix(baseIdentifier, "."+authority.CanonicalDomain) {
			return controlstate.DNSChallengeContext{}, ChallengeRecord{}, "", terminalf("DNS challenge authority is not available")
		}
		record.ZoneID, record.ClaimedZone = authority.ProviderZoneID, true
		record.AuthorityReference = authority.Reference
	}
	record.DesiredOwnedValues, record.PreviouslyOwnedValues = challengeTXTValues(challenge.Presentations)
	expected := challengeTXTValue(challenge.ChallengeDigest)
	return challenge, record, expected, nil
}

func challengeTXTValues(presentations []controlstate.DNSChallengePresentation) (desiredValues, ownedValues []string) {
	desired := make(map[string]struct{}, len(presentations))
	owned := make(map[string]struct{}, len(presentations))
	for _, presentation := range presentations {
		value := challengeTXTValue(presentation.ChallengeDigest)
		owned[value] = struct{}{}
		if presentation.Active {
			desired[value] = struct{}{}
		}
	}
	return mapKeys(desired), mapKeys(owned)
}

func challengeTXTValue(digest [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}
