package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/dnscontroller"
	"github.com/tnldotdev/tnl/internal/testutil"
)

const route53ACMEStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

var route53TestZoneID = flag.String("tnl-route53-zone-id", "", "staging Route 53 hosted zone ID for the opt-in DNS-01 test")

// TestIntegrationRoute53StagingACME uses a fresh DNS name in the existing
// tnl.wtf zone. A disposable control database exercises the actual public URL
// certificate worker; only this test's TXT record is written to Route 53.
func TestIntegrationRoute53StagingACME(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierRoute53)
	if !regexp.MustCompile(`^Z[A-Z0-9]+$`).MatchString(*route53TestZoneID) {
		t.Fatal("-tnl-route53-zone-id must name a Route 53 hosted zone")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	route53Client := route53.NewFromConfig(awsConfig)
	provider, err := dnscontroller.NewRoute53Provider(route53Client)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := dnscontroller.NewAuthoritativeVerifier("")
	if err != nil {
		t.Fatal(err)
	}

	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "route53_acme_staging")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	now := time.Now().UTC()
	for _, service := range []string{"relay-a", "relay-b"} {
		if _, err := database.RegisterRelay(ctx, controlstate.RelayRegistration{
			RelayServiceID: service, RelayID: service + "-ci", RelayRunID: service + "-run", ProtocolVersion: 1,
			RelayAddress: service + ".tnl.wtf:443", TLSServerName: service + ".tnl.wtf",
			InternalRelayAddress: service + ".internal:9445", ConnectionCapacity: 10, StreamCapacity: 10,
		}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	session, err := database.CreateBuiltinControlSession(ctx, "test.tnl.wtf", 1, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	member := session.Identity.Memberships[0]
	principal, err := database.AuthenticateAccessToken(ctx, session.AccessToken, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	domains, err := database.ListTeamDomains(ctx, session.Identity.Identity.ID, member.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	namespace := member.ManagedLabel + ".test.tnl.wtf"
	challengeName := "_acme-challenge." + namespace
	if record, err := route53SmokeTXT(ctx, route53Client, *route53TestZoneID, challengeName); err != nil || record != nil {
		t.Fatalf("fresh challenge name already exists or is unreadable: present=%t error=%v", record != nil, err)
	}
	t.Cleanup(func() { cleanupRoute53SmokeTXT(t, route53Client, *route53TestZoneID, challengeName) })
	hostname := "api." + namespace
	publicURL, err := database.CreatePublicURL(ctx, controlstate.CreatePublicURLRequest{
		TeamID: member.TeamID, DomainID: domains[0].ID, ActingIdentityID: session.Identity.Identity.ID,
		IdempotencyKey: "ci", RequestDigest: sha256.Sum256([]byte(hostname)), CanonicalHostname: hostname,
		Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, MembershipID: member.ID,
		DNSState: controlstate.PublicURLDNSPending, PolicyRevision: 1,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	identifiers := []string{"*." + namespace, namespace}
	run, err := database.CreatePublishRun(ctx, controlstate.PublishRunRequest{
		PublicURLID: publicURL.ID, TeamID: publicURL.TeamID, MembershipID: publicURL.MembershipID, ActingIdentityID: session.Identity.Identity.ID,
		RetrySecret: principal.RetrySecret[:], IdempotencyKey: "ci-run", RequestDigest: sha256.Sum256([]byte("ci-run")), PolicyRevision: 1,
		CertificateCacheKey: namespace, CertificateScope: namespace, CertificateIdentifiers: identifiers,
		CertificateChallenge: "dns-01", ExpectedMutationRevision: publicURL.MutationRevision,
	}, now, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	account, err := database.EnsureACMEAccount(ctx, route53ACMEStagingDirectory, "ci@tnl.dev", now)
	if err != nil {
		t.Fatal(err)
	}
	orders := &singleStagingOrderTransport{base: http.DefaultTransport}
	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: orders}
	account, err = ReconcileACMEAccount(ctx, database, httpClient, account, true, now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := database.CreateCertificateIssuance(ctx, controlstate.CreateCertificateIssuanceRequest{
		Authentication: controlstate.PublishRunAuthentication{PublicURLID: publicURL.ID, PublishRunID: run.PublishRunID,
			PublishRunNumber: run.PublishRunNumber, PublishRunToken: run.PublishRunToken},
		DirectoryURL: account.DirectoryURL, IdempotencyKey: "ci-issuance", RequestDigest: sha256.Sum256(csr), CSRDER: csr,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	dnsChallenges, err := dnscontroller.NewChallengeManager(database, provider, verifier, dnscontroller.Config{
		ManagedDomain: "tnl.wtf", ManagedZoneID: *route53TestZoneID,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &authorizationRecordingStore{Database: database}
	worker, err := NewPublicURLWorker(store, PublicURLConfig{
		WorkerID: "route53_ci", Profile: "tlsserver", HTTPClient: httpClient,
		DNSChallenges: dnsChallenges, PollInterval: time.Second, IdleInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("one ACME staging order for %s", namespace)
	certificateReady := false
	for ctx.Err() == nil {
		if _, err := worker.processOne(ctx); err != nil {
			t.Fatal(err)
		}
		current, err := database.GetCertificateIssuance(ctx, issuance.ID, run.PublishRunToken, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		switch current.State {
		case "waiting_for_install":
			if certificateReady {
				t.Fatal("certificate installation did not persist")
			}
			block, _ := pem.Decode([]byte(current.CertificatePEM))
			if block == nil {
				t.Fatal("ACME staging issued no X.509 certificate")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			for _, hostname := range []string{namespace, "api." + namespace} {
				if err := leaf.VerifyHostname(hostname); err != nil {
					t.Fatalf("issued certificate for %s: %v", hostname, err)
				}
			}
			if count := orders.count.Load(); count != 1 {
				t.Fatalf("ACME new orders = %d, want exactly one", count)
			}
			pendingCleanup := false
			for _, authorization := range store.saved[len(store.saved)-1].Authorizations {
				if authorization.ChallengeType == "dns-01" && authorization.CleanupCompletedAt == nil {
					pendingCleanup = true
				}
			}
			if !pendingCleanup {
				t.Fatal("certificate was not available before DNS cleanup")
			}
			if _, err := database.MarkPublicURLCertificateInstalled(ctx, controlstate.PublishRunAuthentication{
				PublicURLID: publicURL.ID, PublishRunID: run.PublishRunID,
				PublishRunNumber: run.PublishRunNumber, PublishRunToken: run.PublishRunToken,
			}, issuance.ID, leaf.NotAfter, time.Now()); err != nil {
				t.Fatal(err)
			}
			certificateReady = true
			t.Logf("ACME staging certificate ready for %s before DNS cleanup after %s", namespace, time.Since(issuance.CreatedAt).Round(time.Second))
		case "installed":
			if !certificateReady {
				t.Fatal("certificate was installed before the early-ready check")
			}
			cleaned := len(store.saved) != 0 && len(store.saved[len(store.saved)-1].Authorizations) == 2
			if cleaned {
				for _, authorization := range store.saved[len(store.saved)-1].Authorizations {
					cleaned = cleaned && authorization.State == "complete" && authorization.CleanupCompletedAt != nil
				}
			}
			if cleaned {
				record, err := route53SmokeTXT(ctx, route53Client, *route53TestZoneID, challengeName)
				if err != nil || record != nil || orders.count.Load() != 1 {
					t.Fatalf("DNS cleanup or one-order budget: TXT present=%t orders=%d error=%v", record != nil, orders.count.Load(), err)
				}
				t.Logf("ACME staging certificate issued for %s with one order and DNS cleanup complete after %s", namespace, time.Since(issuance.CreatedAt).Round(time.Second))
				return
			}
		case "failed", "canceled":
			cause := "unknown"
			for _, saved := range store.saved {
				if saved.LastError != "" {
					cause = saved.LastError
				}
			}
			t.Fatalf("ACME staging issuance for %s ended in %s: %s", namespace, current.State, cause)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	t.Fatalf("ACME staging issuance for %s did not finish: %v", namespace, ctx.Err())
}

type singleStagingOrderTransport struct {
	base  http.RoundTripper
	count atomic.Int32
}

func (t *singleStagingOrderTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/new-order") && t.count.Add(1) != 1 {
		return nil, fmt.Errorf("ACME staging check exceeded its one-order budget")
	}
	return t.base.RoundTrip(request)
}

func route53SmokeTXT(ctx context.Context, client *route53.Client, zoneID, name string) (*types.ResourceRecordSet, error) {
	result, err := client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID), StartRecordName: aws.String(name), StartRecordType: types.RRTypeTxt,
		MaxItems: aws.Int32(1),
	})
	if err != nil {
		return nil, err
	}
	if len(result.ResourceRecordSets) != 0 && strings.EqualFold(aws.ToString(result.ResourceRecordSets[0].Name), name+".") &&
		result.ResourceRecordSets[0].Type == types.RRTypeTxt {
		return &result.ResourceRecordSets[0], nil
	}
	return nil, nil
}

func cleanupRoute53SmokeTXT(t *testing.T, client *route53.Client, zoneID, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	record, err := route53SmokeTXT(ctx, client, zoneID, name)
	if err != nil {
		t.Errorf("inspect test-owned DNS challenge: %v", err)
		return
	}
	if record == nil {
		return
	}
	change, err := client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch:  &types.ChangeBatch{Changes: []types.Change{{Action: types.ChangeActionDelete, ResourceRecordSet: record}}},
	})
	if err != nil || change == nil || change.ChangeInfo == nil {
		t.Errorf("remove test-owned DNS challenge: %v", err)
		return
	}
	for ctx.Err() == nil {
		status, err := client.GetChange(ctx, &route53.GetChangeInput{Id: change.ChangeInfo.Id})
		if err != nil {
			t.Errorf("check test-owned DNS cleanup: %v", err)
			return
		}
		if status.ChangeInfo != nil && status.ChangeInfo.Status == types.ChangeStatusInsync {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	t.Errorf("test-owned DNS challenge cleanup did not reach INSYNC: %v", ctx.Err())
}
