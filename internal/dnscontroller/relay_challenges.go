package dnscontroller

import (
	"context"
	"errors"
	"strings"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

type RelayChallengeStore interface {
	GetRelayDNSChallengeContext(context.Context, string) (controlstate.RelayDNSChallengeContext, error)
	WithDNSChallengeLock(context.Context, string, func() error) error
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
	_, err := m.reconcile(ctx, orderID, "presenting")
	return err
}

func (m *RelayChallengeManager) Verify(ctx context.Context, orderID string) (bool, error) {
	return m.reconcile(ctx, orderID, "presented")
}

func (m *RelayChallengeManager) Cleanup(ctx context.Context, orderID string) error {
	_, err := m.reconcile(ctx, orderID, "cleaning")
	return err
}

func (m *RelayChallengeManager) reconcile(ctx context.Context, orderID, state string) (bool, error) {
	initial, err := m.store.GetRelayDNSChallengeContext(ctx, orderID)
	if err != nil {
		return false, err
	}
	recordName := "_acme-challenge." + initial.TLSServerName
	verified := false
	err = m.store.WithDNSChallengeLock(ctx, recordName, func() error {
		challenge, record, expected, err := m.challengeRecord(ctx, orderID)
		if err != nil {
			return err
		}
		if challenge.State != state && !(state == "cleaning" && challenge.State == "failed_cleaning") || record.RecordName != recordName {
			return terminalf("cannot reconcile relay DNS challenge in state %q for %q", challenge.State, record.RecordName)
		}
		zone, err := m.provider.ReconcileChallenge(ctx, record)
		if err == nil && state == "presented" {
			verified, err = m.verifier.VerifyChallenge(ctx, record.RecordName, expected, zone.Nameservers)
		}
		return err
	})
	return verified, err
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
	record.DesiredOwnedValues, record.PreviouslyOwnedValues = challengeTXTValues(challenge.Presentations)
	expected := challengeTXTValue(challenge.ChallengeDigest)
	return challenge, record, expected, nil
}
