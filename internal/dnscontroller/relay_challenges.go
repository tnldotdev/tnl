package dnscontroller

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

type RelayChallengeStore interface {
	ChallengeChangeStore
	GetRelayDNSChallengeContext(context.Context, string) (controlstate.RelayDNSChallengeContext, error)
	WithDNSChallengeLock(context.Context, string, func() error) error
}

type RelayChallengeManager struct {
	store        RelayChallengeStore
	provider     ChallengeProvider
	verifier     ChallengeVerifier
	serverDomain string
	zoneID       string
	observer     DNSObserver
}

func (m *RelayChallengeManager) SetObserver(observer DNSObserver) { m.observer = observer }

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
	started := time.Now()
	_, err := m.reconcile(ctx, orderID, controlstate.RelayCertificatePresenting)
	observeDNS(m.observer, "relay_challenge", "provider", started, true, err)
	return err
}

func (m *RelayChallengeManager) Verify(ctx context.Context, orderID string) (bool, error) {
	started := time.Now()
	verified, err := m.reconcile(ctx, orderID, controlstate.RelayCertificatePresented)
	observeDNS(m.observer, "relay_challenge", "verify", started, verified, err)
	return verified, err
}

func (m *RelayChallengeManager) Cleanup(ctx context.Context, orderID string) error {
	started := time.Now()
	_, err := m.reconcile(ctx, orderID, controlstate.RelayCertificateCleaning)
	observeDNS(m.observer, "relay_challenge", "cleanup", started, true, err)
	return err
}

func (m *RelayChallengeManager) reconcile(ctx context.Context, orderID string, state controlstate.RelayCertificateOrderState) (bool, error) {
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
		if challenge.State != state && !(state == controlstate.RelayCertificateCleaning && challenge.State == controlstate.RelayCertificateFailedCleaning) || record.RecordName != recordName {
			return terminalf("cannot reconcile relay DNS challenge in state %q for %q", challenge.State, record.RecordName)
		}
		verified, err = reconcileChallengeChange(ctx, m.store, m.provider, m.verifier, record, expected, string(state))
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
