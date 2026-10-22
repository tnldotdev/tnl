package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestServiceRunLifecycleBoundary(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		state         serviceRunLifecycleState
		valid, active bool
	}{
		{serviceRunPrepared, true, false}, {serviceRunStarting, true, true},
		{serviceRunReady, true, true}, {serviceRunClosed, true, false},
		{"", false, false}, {"expired", false, false}, {"assigned", false, false},
	} {
		t.Run(string(tc.state), func(t *testing.T) {
			if tc.state.valid() != tc.valid || tc.state.active() != tc.active {
				t.Fatal("private run lifecycle crossed the active publisher boundary")
			}
			run := controlstatedb.ControlServiceRun{State: string(tc.state), PublisherExpiresAt: timestamptz(now.Add(time.Nanosecond))}
			if activeServiceRun(run, now) != tc.active {
				t.Fatal("stored run crossed the active publisher boundary")
			}
			if activeServiceRun(run, now.Add(time.Nanosecond)) {
				t.Fatal("publisher lease remained active at its expiry")
			}
			run.ClosedAt = timestamptz(now)
			if activeServiceRun(run, now) {
				t.Fatal("closed publisher run remained active")
			}
		})
	}
	for _, state := range []string{"assigned", "connected", "ready", "closed"} {
		if _, err := privateAssignmentState(state); err != nil {
			t.Fatalf("assignment state %s: %v", state, err)
		}
	}
	for _, state := range []string{"prepared", "starting", "draining", "expired", ""} {
		if _, err := privateAssignmentState(state); !errors.Is(err, ErrServiceAccess) {
			t.Fatalf("accepted invalid private assignment state %s", state)
		}
	}
}

func TestServiceRunAssignmentBindingBoundary(t *testing.T) {
	const suffix = "AAAAAAAAAAAAAAAAAAAAAA"
	service, run, connection := "svc_"+suffix, "srun_"+suffix, "pc_"+suffix
	binding, err := checkedPrivateAssignmentBinding(service, run, connection, math.MaxInt64, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	slot := controlstatedb.ControlServiceConnectionSlot{ServiceID: service, ServiceRunID: run, PublisherConnectionID: connection, RunNumber: math.MaxInt64, ConnectionAssignmentRevision: math.MaxInt64}
	if !binding.matches(slot) {
		t.Fatal("maximum signed database binding did not round trip")
	}
	for _, tc := range []struct {
		name   string
		change func(*controlstatedb.ControlServiceConnectionSlot)
	}{
		{"service", func(s *controlstatedb.ControlServiceConnectionSlot) { s.ServiceID += "B" }},
		{"run", func(s *controlstatedb.ControlServiceConnectionSlot) { s.ServiceRunID += "B" }},
		{"connection", func(s *controlstatedb.ControlServiceConnectionSlot) { s.PublisherConnectionID += "B" }},
		{"number", func(s *controlstatedb.ControlServiceConnectionSlot) { s.RunNumber-- }},
		{"revision", func(s *controlstatedb.ControlServiceConnectionSlot) { s.ConnectionAssignmentRevision-- }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crossed := slot
			tc.change(&crossed)
			if binding.matches(crossed) {
				t.Fatal("crossed assignment binding accepted")
			}
		})
	}
	for _, tc := range []struct{ number, revision int64 }{{0, 1}, {-1, 1}, {1, 0}, {1, -1}, {math.MinInt64, 1}} {
		if _, err := checkedPrivateAssignmentBinding(service, run, connection, tc.number, tc.revision); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("invalid signed binding accepted")
		}
	}
	for _, value := range []int64{math.MinInt64, -1, 0, math.MaxInt64} {
		if _, err := nextPrivateRevision(value); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("invalid or overflowing increment accepted")
		}
	}
	if next, err := nextPrivateRevision(math.MaxInt64 - 1); err != nil || next != math.MaxInt64 {
		t.Fatalf("last representable increment: %d, %v", next, err)
	}
}

func TestServiceRunCredentialHashVectors(t *testing.T) {
	const secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const hash = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
	digest, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(secret))
	if err != nil || hex.EncodeToString(digest[:]) != hash {
		t.Fatalf("managed run hash bytes changed: %v", err)
	}
	stored, err := serviceSecretDigest(secret)
	if err != nil || !bytes.Equal(stored, digest[:]) {
		t.Fatal("managed token no longer matches stored digest bytes")
	}
	for _, invalid := range []string{"", secret + "=", secret[:42], secret[:42] + "B", "prs_" + secret, " " + secret} {
		if _, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(invalid)); err == nil {
			t.Fatal("noncanonical or prefixed managed run token accepted")
		}
	}
	seed, err := credentials.NewAssignmentSeed()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(seed)); err == nil {
		t.Fatal("assignment seed authorized a managed run")
	}
}

func TestServiceMetadataStoredBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, encoded string
		revision                int64
		valid                   bool
	}{
		{"absent", "tcp", "", 1, true}, {"null", "postgres", "null", 2, true},
		{"spaced null", "http", " \n null \t", 3, true},
		{"system trust", "postgres", `{"hostname":"db.internal","system":true,"digest":"` + systemTrustDigest("db.internal") + `"}`, 4, true},
		{"corrupt JSON", "tcp", `{"pem":"sensitive trust`, 1, false},
		{"wrong shape", "tcp", `[]`, 1, false},
		{"invalid trust", "tcp", `{"hostname":"db.internal","system":true,"pem":"sensitive trust","digest":"wrong"}`, 1, false},
		{"unknown protocol", "unknown", "null", 1, false},
		{"zero revision", "tcp", "null", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := controlstatedb.ControlService{Protocol: tc.protocol, TlsMetadata: []byte(tc.encoded), TrustRevision: tc.revision, PublisherPool: true}
			metadata, err := checkedServiceMetadata(row)
			if (err == nil) != tc.valid {
				t.Fatalf("metadata decode: %v", err)
			}
			if !tc.valid {
				if !errors.Is(err, ErrServiceMetadata) || !reflect.DeepEqual(metadata, ServiceMetadata{}) || strings.Contains(err.Error(), "sensitive trust") {
					t.Fatal("corrupt metadata lost classification or exposed partial trust")
				}
				if record, err := checkedServiceRecord(row); !errors.Is(err, ErrServiceMetadata) || !reflect.DeepEqual(record, ServiceRecord{}) {
					t.Fatal("service read did not propagate corrupt trust")
				}
			} else if metadata.Protocol != tc.protocol || metadata.TrustRevision != tc.revision || !metadata.PublisherPool {
				t.Fatal("metadata projection lost saved fields")
			}
		})
	}
}

func systemTrustDigest(host string) string {
	// these bytes are the existing target trust snapshot context.
	digest := sha256.Sum256([]byte(host + "\x00system\x00"))
	return hex.EncodeToString(digest[:])
}

func TestServiceRunPublicURLProjectionBoundary(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	base := controlstatedb.ControlPublicUrl{
		ID: "url", TeamID: "team", DomainID: "domain", MembershipID: text("member"),
		CanonicalHostname: "app.example.test", Target: "http://127.0.0.1:1234", Namespace: "example.test",
		PublicURLScope: "member", Purpose: "app", AccessMode: "restricted", PolicyRevision: 17,
		LifecycleState: "enabled", DnsAuthorityReference: text("dns-authority"), DnsState: "ready",
		NextPublishRunNumber: 23, MutationRevision: 31, Ephemeral: true, ExpiresAt: timestamptz(expires),
		CreatedAt: timestamptz(now), UpdatedAt: timestamptz(now.Add(time.Second)), ServiceProtocol: "http", PublisherPool: true,
	}
	fixture, err := json.Marshal(struct {
		controlstatedb.ControlPublicUrl
		OpenPublishRunID string
	}{base, "open-run"})
	if err != nil {
		t.Fatal(err)
	}
	var retry controlstatedb.GetPublicURLByCreatorIdempotencyRow
	var identity controlstatedb.GetIdentityPublicURLRow
	var list controlstatedb.ListIdentityPublicURLsRow
	var authorized controlstatedb.ListAuthorizedPublicURLsDataRow
	var auth controlstatedb.GetPublicURLForAuthorizationDataRow
	for _, row := range []any{&retry, &identity, &list, &authorized, &auth} {
		if err := json.Unmarshal(fixture, row); err != nil {
			t.Fatal(err)
		}
	}
	expected := PublicURL{ID: "url", TeamID: "team", DomainID: "domain", MembershipID: "member", CanonicalHostname: "app.example.test", Target: "http://127.0.0.1:1234", Namespace: "example.test", PublicURLScope: "member", Purpose: "app", AccessMode: "restricted", PolicyRevision: 17, LifecycleState: "enabled", DNSAuthorityReference: "dns-authority", DNSState: "ready", NextPublishRunNumber: 23, MutationRevision: 31, AuthorizationPublishRunNumber: 23, Ephemeral: true, ExpiresAt: &expires, OpenPublishRunID: "open-run", CreatedAt: now, UpdatedAt: now.Add(time.Second), ServiceProtocol: "http", PublisherPool: true}
	for name, actual := range map[string]PublicURL{
		"model": publicURLFromModel(base, "open-run"), "retry": publicURLFromIdempotencyRow(retry),
		"identity": publicURLFromIdentityRow(identity), "list": publicURLFromListRow(list), "authorized list": publicURLFromAuthorizedListRow(authorized),
	} {
		t.Run(name, func(t *testing.T) {
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("projection fields differ:\nactual: %#v\nexpected: %#v", actual, expected)
			}
		})
	}
	for _, number := range []int64{0, 7, math.MaxInt64} {
		auth.AuthorizationPublishRunNumber = number
		actual := publicURLFromAuthorizationRow(auth)
		expected.AuthorizationPublishRunNumber = uint64(number)
		if !reflect.DeepEqual(actual, expected) {
			t.Fatal("authorization-specific run number override changed other projection fields")
		}
	}
}
