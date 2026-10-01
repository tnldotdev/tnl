package dnscontroller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

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
	ChallengeChangeStore
	GetDNSAuthority(context.Context, string) (controlstate.DNSAuthority, error)
	GetDNSChallengeContext(context.Context, string, string) (controlstate.DNSChallengeContext, error)
	WithDNSChallengeLock(context.Context, string, func() error) error
}

var ErrChallengesNotConfigured = terminalf("DNS challenge automation is not configured")

type ChallengeProvider interface {
	ReconcileChallenge(context.Context, ChallengeRecord) (Zone, error)
	RefreshChallenge(context.Context, ChallengeRecord) (Zone, error)
	ChangeReady(context.Context, string) (bool, error)
}

type ChallengeChangeStore interface {
	GetDNSChallengeChange(context.Context, string, string) (controlstate.DNSChallengeChange, bool, error)
	SaveDNSChallengeChange(context.Context, string, string, [32]byte, string, time.Time) error
}

var errChallengePropagationPending = errors.New("dnscontroller: Route 53 challenge change is still propagating")

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

func (m *ChallengeManager) Present(ctx context.Context, publicURLID, authorizationID string) error {
	started := time.Now()
	_, err := m.reconcile(ctx, publicURLID, authorizationID, "presenting")
	observeDNS(m.config.Observer, "public_url_challenge", "provider", started, true, err)
	return err
}

func (m *ChallengeManager) Verify(ctx context.Context, publicURLID, authorizationID string) (bool, error) {
	started := time.Now()
	verified, err := m.reconcile(ctx, publicURLID, authorizationID, "presented")
	observeDNS(m.config.Observer, "public_url_challenge", "verify", started, verified, err)
	return verified, err
}

func (m *ChallengeManager) Cleanup(ctx context.Context, publicURLID, authorizationID string) error {
	started := time.Now()
	_, err := m.reconcile(ctx, publicURLID, authorizationID, "cleaning")
	observeDNS(m.config.Observer, "public_url_challenge", "cleanup", started, true, err)
	return err
}

func (m *ChallengeManager) reconcile(ctx context.Context, publicURLID, authorizationID, state string) (bool, error) {
	initial, err := m.store.GetDNSChallengeContext(ctx, publicURLID, authorizationID)
	if err != nil {
		return false, err
	}
	recordName := "_acme-challenge." + strings.TrimPrefix(initial.Identifier, "*.")
	verified := false
	err = m.store.WithDNSChallengeLock(ctx, recordName, func() error {
		challenge, record, expected, err := m.challengeRecord(ctx, publicURLID, authorizationID)
		if err != nil {
			return err
		}
		if challenge.State != state || record.RecordName != recordName {
			return terminalf("cannot reconcile DNS challenge in state %q for %q", challenge.State, record.RecordName)
		}
		verified, err = reconcileChallengeChange(ctx, m.store, m.provider, m.verifier, record, expected, state)
		return err
	})
	return verified, err
}

// the per-name lock orders every write and receipt for a shared TXT record,
// including wildcard and exact-name authorizations across control processes.
func reconcileChallengeChange(
	ctx context.Context, store ChallengeChangeStore, provider ChallengeProvider, verifier ChallengeVerifier,
	record ChallengeRecord, expected, state string,
) (bool, error) {
	values := slices.Clone(record.DesiredOwnedValues)
	slices.Sort(values)
	digest := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	zoneID := canonicalZoneID(record.ZoneID)
	change, found, err := store.GetDNSChallengeChange(ctx, zoneID, record.RecordName)
	if err != nil {
		return false, err
	}
	// do not rewrite a TXT record while its last Route 53 change is pending,
	// even if the desired values changed. a listing may show the new value before
	// DNS replicas have it; wait for the durable change receipt to complete.
	checkedReady := false
	if found {
		if change.DesiredDigest == digest && state == "presenting" {
			return false, nil
		}
		checkedReady, err = provider.ChangeReady(ctx, change.ChangeID)
		if err != nil {
			return false, err
		}
		if !checkedReady {
			if state == "cleaning" || change.DesiredDigest != digest {
				return false, errChallengePropagationPending
			}
			return false, nil
		}
	}
	zone, err := provider.ReconcileChallenge(ctx, record)
	if err != nil {
		return false, err
	}
	if zone.ChangeID == "" && (!found || change.DesiredDigest != digest) && len(values) != 0 {
		// a Route 53 write may succeed before a crash or lost response. an
		// idempotent UPSERT obtains another durable receipt for the same values.
		zone, err = provider.RefreshChallenge(ctx, record)
		if err != nil {
			return false, err
		}
	}
	if zone.ChangeID != "" {
		if err := store.SaveDNSChallengeChange(ctx, zoneID, record.RecordName, digest, zone.ChangeID, time.Now()); err != nil {
			return false, err
		}
		change, found = controlstate.DNSChallengeChange{DesiredDigest: digest, ChangeID: zone.ChangeID}, true
		checkedReady = false
	}
	if state == "presenting" {
		if !found || change.DesiredDigest != digest {
			return false, errors.New("dnscontroller: challenge presentation has no Route 53 change receipt")
		}
		return false, nil
	}
	if state == "cleaning" && (!found || change.DesiredDigest != digest) {
		// an already absent record needs no further deletion. a later presentation
		// obtains its own change receipt before validation.
		return false, nil
	}
	if !found || change.DesiredDigest != digest {
		return false, errors.New("dnscontroller: challenge has no current Route 53 change receipt")
	}
	if !checkedReady {
		checkedReady, err = provider.ChangeReady(ctx, change.ChangeID)
		if err != nil {
			return false, err
		}
	}
	if !checkedReady {
		if state == "cleaning" {
			return false, errChallengePropagationPending
		}
		return false, nil
	}
	if state == "presented" {
		return verifier.VerifyChallenge(ctx, record.RecordName, expected, zone.Nameservers)
	}
	return false, nil
}

func (m *ChallengeManager) challengeRecord(
	ctx context.Context,
	publicURLID, authorizationID string,
) (controlstate.DNSChallengeContext, ChallengeRecord, string, error) {
	challenge, err := m.store.GetDNSChallengeContext(ctx, publicURLID, authorizationID)
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
