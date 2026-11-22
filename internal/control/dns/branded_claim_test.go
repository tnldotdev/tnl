package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

type brandedClaimFixture struct {
	proof, served, parent, removed bool
	mappingErr                     error
}

func (*brandedClaimFixture) DelegationNameservers(context.Context, string) ([]string, error) {
	return []string{"ns1.aws.test", "ns2.aws.test", "ns3.aws.test", "ns4.aws.test"}, nil
}

func (f *brandedClaimFixture) VerifyNameserverMapping(context.Context, []string, []string) error {
	return f.mappingErr
}

func (f *brandedClaimFixture) VerifyClaimProof(context.Context, string, string, string, []string) (bool, error) {
	return f.proof, nil
}

func (f *brandedClaimFixture) VerifyBrandedZone(context.Context, string, []string) (bool, error) {
	return f.served, nil
}

func (f *brandedClaimFixture) VerifyParentDelegation(context.Context, string, []string) (bool, error) {
	return f.parent, nil
}

func (f *brandedClaimFixture) VerifyDelegationRemoved(context.Context, string, []string) (bool, error) {
	return f.removed, nil
}

func TestBrandedClaimOrdersProofZoneDelegationAndRelease(t *testing.T) {
	now := time.Now()
	work := testDNSWork(now)
	work.DelegationSetID, work.NameserverDomain = "NBRANDED", "dns.example.test"
	work.ClaimProofName, work.ClaimProofValue = "_tnl-claim-dev.example.test", "current-proof"
	work.ClaimExpiresAt = now.Add(time.Hour)
	names := []string{"ns1.dns.example.test", "ns2.dns.example.test", "ns3.dns.example.test", "ns4.dns.example.test"}
	fixture := &brandedClaimFixture{mappingErr: errors.New("ns3 mapping is wrong")}
	provider := &providerStub{zone: Zone{ID: "ZBRANDED", Nameservers: names}}
	verifier := &verifierStub{verified: true}
	w := testDNSWorker(t, &dnsStoreStub{releaseReady: true}, provider, verifier, now)
	w.config.BrandedProvider, w.config.BrandedVerifier = fixture, fixture
	advance := func() {
		t.Helper()
		if err := w.advanceAuthority(t.Context(), &work, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.advanceAuthority(t.Context(), &work, now); !errors.Is(err, fixture.mappingErr) || len(work.Nameservers) != 0 {
		t.Fatalf("published instructions with wrong mapping: %v / %v", err, work.Nameservers)
	}
	fixture.mappingErr = nil
	advance()
	advance()
	if !slices.Equal(work.Nameservers, names) || provider.ensureCalls != 0 {
		t.Fatal("missing proof created a zone")
	}
	fixture.proof = true
	advance()
	if work.ClaimProofVerifiedAt.IsZero() || provider.ensureCalls != 0 {
		t.Fatal("proof wasn't saved before zone creation")
	}
	advance()
	if provider.ensureCalls != 1 || work.ProviderZoneID != "" {
		t.Fatal("advertised delegation before its authoritative servers were ready")
	}
	fixture.served = true
	advance()
	advance()
	if work.ProviderZoneID != "ZBRANDED" || verifier.calls != 0 || work.State != controlstate.DNSAuthorityPending {
		t.Fatal("child authority was treated as parent delegation")
	}
	fixture.parent = true
	advance()
	if work.State != controlstate.DNSAuthorityReady || verifier.calls != 1 {
		t.Fatal("correct delegation didn't become ready")
	}
	work.State = controlstate.DNSAuthorityReleasing
	advance()
	if provider.releaseCalls != 0 {
		t.Fatal("deleted a still-delegated zone")
	}
	fixture.removed = true
	advance()
	if provider.releaseCalls != 1 || work.State != controlstate.DNSAuthorityReleased {
		t.Fatal("didn't release after removing delegation")
	}
}

func TestParentDelegationMustBeAReferralForExactChild(t *testing.T) {
	domain := "dev.example.test"
	names := []string{"ns1.tnl.test", "ns2.tnl.test", "ns3.tnl.test", "ns4.tnl.test"}
	referral := &mdns.Msg{}
	for _, ns := range names {
		rr, err := mdns.NewRR(domain + ". 60 IN NS " + ns + ".")
		if err != nil {
			t.Fatal(err)
		}
		referral.Ns = append(referral.Ns, rr)
	}
	if !matchesDelegationReferral(referral, domain, names) || delegationRemoved(referral, domain, "example.test", names) {
		t.Fatal("correct delegation wasn't distinguished from removal")
	}
	child := referral.Copy()
	child.Authoritative = true
	child.Answer, child.Ns = child.Ns, nil
	if matchesDelegationReferral(child, domain, names) || delegationRemoved(child, domain, "example.test", names) {
		t.Fatal("used a child answer as parent evidence")
	}
	if matchesDelegationReferral(referral, "elsewhere.example.test", names) {
		t.Fatal("accepted the wrong child owner")
	}
}

func TestBrandedClaimExpiryDoesNotCreateZone(t *testing.T) {
	now := time.Now()
	work := testDNSWork(now)
	work.DelegationSetID = "NBRANDED"
	work.ClaimExpiresAt = now
	provider := &providerStub{}
	w := testDNSWorker(t, &dnsStoreStub{}, provider, &verifierStub{}, now)
	if err := w.advanceAuthority(t.Context(), &work, now); err != nil ||
		work.State != controlstate.DNSAuthorityReleasing || provider.ensureCalls != 0 {
		t.Fatalf("expired claim started work: %s / %d / %v", work.State, provider.ensureCalls, err)
	}
}

func TestBrandedNameserverMappingReportsWrongName(t *testing.T) {
	backend := []string{"ns1.aws.test", "ns2.aws.test", "ns3.aws.test", "ns4.aws.test"}
	branded := []string{"ns1.tnl.test", "ns2.tnl.test", "ns3.tnl.test", "ns4.tnl.test"}
	for _, wrong := range []bool{false, true} {
		t.Run(fmt.Sprint(wrong), func(t *testing.T) {
			server := verifierDNS(t, func(_ string, request *mdns.Msg) *mdns.Msg {
				q := request.Question[0]
				number := strings.Split(q.Name, ".")[0][2:]
				if wrong && q.Name == "ns3.tnl.test." && q.Qtype == mdns.TypeAAAA {
					number = "99"
				}
				var answer string
				switch q.Qtype {
				case mdns.TypeA:
					answer = q.Name + " 60 IN A 8.8.4." + number
				case mdns.TypeAAAA:
					answer = q.Name + " 60 IN AAAA 2600:abcd::" + number
				default:
					return verifierResponse(t, request, true, mdns.RcodeSuccess)
				}
				return verifierResponse(t, request, true, mdns.RcodeSuccess, answer)
			})
			v, err := NewAuthoritativeVerifier(server)
			if err != nil {
				t.Fatal(err)
			}
			err = v.VerifyNameserverMapping(t.Context(), branded, backend)
			if !wrong && err != nil {
				t.Fatal(err)
			}
			if wrong {
				var mapping *nameserverSetupError
				if !errors.As(err, &mapping) || mapping.host != branded[2] {
					t.Fatalf("did not name the incorrect server: %v", err)
				}
			}
		})
	}
}

func TestBrandedProofOnlyDialsPublicAuthority(t *testing.T) {
	for _, invalid := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "100.64.0.1", "::1", "fd00::1", "64:ff9b::7f00:1", "2002:7f00:1::"} {
		if publicDNSAddress(netip.MustParseAddr(invalid)) {
			t.Fatalf("could dial non-public address %s", invalid)
		}
	}
}
