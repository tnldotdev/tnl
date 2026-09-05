package dnscontroller

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

type RelayChallengeStore interface {
	GetRelayDNSChallengeContext(context.Context, string) (controlstate.RelayDNSChallengeContext, error)
}

type RelayChallengeManager struct {
	store        RelayChallengeStore
	provider     ChallengeProvider
	verifier     ChallengeVerifier
	serverDomain string
	zoneID       string
}

func NewRelayChallengeManager(
	store RelayChallengeStore,
	provider ChallengeProvider,
	verifier ChallengeVerifier,
	serverDomain, zoneID string,
) (*RelayChallengeManager, error) {
	if store == nil || provider == nil || verifier == nil || serverDomain == "" || zoneID == "" {
		return nil, errors.New("dnscontroller: invalid relay DNS challenge configuration")
	}
	return &RelayChallengeManager{
		store: store, provider: provider, verifier: verifier, serverDomain: serverDomain, zoneID: zoneID,
	}, nil
}

func (m *RelayChallengeManager) Present(ctx context.Context, orderID string) error {
	challenge, record, _, err := m.challengeRecord(ctx, orderID)
	if err != nil {
		return err
	}
	if challenge.State != "presenting" {
		return terminalf("cannot present relay DNS challenge in state %q", challenge.State)
	}
	_, err = m.provider.ReconcileChallenge(ctx, record)
	return err
}

func (m *RelayChallengeManager) Verify(ctx context.Context, orderID string) (bool, error) {
	challenge, record, expected, err := m.challengeRecord(ctx, orderID)
	if err != nil {
		return false, err
	}
	if challenge.State != "presented" {
		return false, terminalf("cannot verify relay DNS challenge in state %q", challenge.State)
	}
	zone, err := m.provider.ReconcileChallenge(ctx, record)
	if err != nil {
		return false, err
	}
	return m.verifier.VerifyChallenge(ctx, record.RecordName, expected, zone.Nameservers)
}

func (m *RelayChallengeManager) Cleanup(ctx context.Context, orderID string) error {
	challenge, record, _, err := m.challengeRecord(ctx, orderID)
	if err != nil {
		return err
	}
	if challenge.State != "cleaning" && challenge.State != "failed_cleaning" {
		return terminalf("cannot clean relay DNS challenge in state %q", challenge.State)
	}
	_, err = m.provider.ReconcileChallenge(ctx, record)
	return err
}

func (m *RelayChallengeManager) challengeRecord(
	ctx context.Context,
	orderID string,
) (controlstate.RelayDNSChallengeContext, ChallengeRecord, string, error) {
	challenge, err := m.store.GetRelayDNSChallengeContext(ctx, orderID)
	if err != nil {
		return controlstate.RelayDNSChallengeContext{}, ChallengeRecord{}, "", err
	}
	if challenge.TLSServerName != m.serverDomain && !strings.HasSuffix(challenge.TLSServerName, "."+m.serverDomain) {
		return controlstate.RelayDNSChallengeContext{}, ChallengeRecord{}, "", terminalf("relay DNS challenge is outside the server domain")
	}
	record := ChallengeRecord{
		ZoneID: m.zoneID, ZoneDomain: m.serverDomain,
		RecordName: "_acme-challenge." + challenge.TLSServerName,
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
