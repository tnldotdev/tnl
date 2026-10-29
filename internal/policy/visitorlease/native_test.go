package visitorlease

import (
	"bytes"
	"crypto/ed25519"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func nativeGuardFixture(t *testing.T) (*Lease, Update, visitortoken.VerifiedPermission, tunnelv1.StreamReservation) {
	t.Helper()
	id := func(prefix, letter string) string { return prefix + strings.Repeat(letter, 22) }
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: id("svc_", "A")}
	l, err := New(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	nativeKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	digest, _ := visitortoken.KeyDigest(nativeKey.Public())
	now := time.Now()
	u := Update{View: visitortoken.View{Issuer: "https://control.example.test", Scope: scope, Hostname: "service.example.test", Port: 15432, VisitorPolicyRevision: 1, MetadataRevision: 5, ObservedAt: now, ValidUntil: now.Add(10 * time.Second)}.WithVerificationKeys(map[string]ed25519.PublicKey{"first": key.Public().(ed25519.PublicKey)}), KeyRevision: 1, Enabled: true, Snapshot: true}
	a := controlv1.StreamCapacityAllocation{Id: id("salloc_", "B"), Resource: controlv1.VisitorResourceScope{Kind: "service", Id: scope.ID}, RunId: id("srun_", "C"), RunNumber: 1, IngressId: "ingress", IngressRunId: "process", IngressLeaseRevision: 1, Capacity: 2, ObservedAt: now, ValidUntil: now.Add(2 * time.Second), ReservationKey: bytes.Repeat([]byte{3}, 32)}
	u.Allocations = map[string]controlv1.StreamCapacityAllocation{a.Id: a}
	if err := l.Apply(l.Begin(), u); err != nil {
		t.Fatal(err)
	}
	view, _, _ := l.Current()
	subject := visitortoken.Device{IdentityID: id("ident_", "D"), SessionID: id("cs_", "I"), DeviceID: id("vdev_", "E"), KeySHA256: digest}
	token, err := visitortoken.Sign(view.Issuer, "first", key, visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: 1, Subject: subject, ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	session, visitor := id("cns_", "F"), id("vc_", "G")
	message, err := visitortoken.NativeProofMessage(token, session, visitor, a.RunId, 1, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	peer, _ := visitortoken.NativeSubject(subject)
	permission, err := visitortoken.VerifyNativeSession(token, view, peer, session, visitor, a.RunId, 1, 5, nil, nativeKey.Public().(ed25519.PublicKey), ed25519.Sign(nativeKey, message), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := tunnelv1.StreamReservation{ID: id("sres_", "H"), AllocationID: a.Id, Sequence: 1, ResourceKind: "service", ResourceID: scope.ID, RunID: a.RunId, RunNumber: 1, VisitorConnectionID: visitor, IngressID: a.IngressId, IngressRunID: a.IngressRunId, IngressLeaseRevision: 1}
	signReservationFixture(t, a.ReservationKey, &h, "192.0.2.1")
	return l, u, permission, h
}

func TestPolicyNativeMetadataSurvivesDecode(t *testing.T) {
	for _, revision := range []int64{-1, 0, 7} {
		wire := controlv1.VisitorPolicyUpdate{Policy: controlv1.VisitorPolicySnapshot{
			Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: "svc_" + strings.Repeat("A", 22)},
			Port:     15432, MetadataRevision: revision,
		}}
		update, err := Decode(wire)
		if revision < 0 {
			if err == nil {
				t.Fatal("negative metadata revision accepted")
			}
		} else if err != nil || update.View.MetadataRevision != revision {
			t.Fatal("authenticated metadata revision was lost during decoding", revision, err)
		}
	}
}

func TestPolicyNativeReservationLossFencesBeforeCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, u, permission, h := nativeGuardFixture(t)
		source := netip.MustParseAddr(h.SourceIP)
		r, err := l.PrepareReservationFrom(h, source, func() {})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		entered, release := make(chan struct{}), make(chan struct{})
		g, err := l.BindNative(permission, source, 5, r, func() { close(entered); <-release })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Current(); err != nil {
			t.Fatal(err)
		}
		u.Allocations = nil
		finished := make(chan error, 1)
		go func() { finished <- l.Apply(l.Begin(), u) }()
		<-entered
		if _, err := g.Current(); err == nil {
			t.Fatal("reservation loss remained usable while its stop callback was held")
		}
		view, _, _ := l.Current()
		if err := visitortoken.CheckCurrent(permission, view, time.Now()); err != nil {
			t.Fatal("test revoked permission instead of its independent reservation", err)
		}
		close(release)
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
		g.Close()
	})
}

func TestPolicyNativeReservationCloseAndExpiryAreSynchronous(t *testing.T) {
	for _, closeReservation := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			l, _, permission, h := nativeGuardFixture(t)
			r, err := l.PrepareReservationFrom(h, netip.MustParseAddr(h.SourceIP), func() { t.Error("suppressed reservation callback ran") })
			if err != nil {
				t.Fatal(err)
			}
			g, err := l.BindNative(permission, netip.MustParseAddr(h.SourceIP), 5, r, func() {})
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			r.timer.Stop()
			if closeReservation {
				r.Close()
			} else {
				time.Sleep(3 * time.Second)
			}
			if _, err := g.Current(); err == nil {
				t.Fatal("native use ignored reservation membership or its absolute allocation deadline")
			}
			r.Close()
		})
	}
}

func TestPolicyNativeMetadataAndPermissionRemovalFenceWithoutCallbacks(t *testing.T) {
	l, u, permission, _ := nativeGuardFixture(t)
	g, err := l.BindNative(permission, netip.MustParseAddr("192.0.2.1"), 5, nil, func() {})
	if err != nil {
		t.Fatal(err)
	}
	u.View.MetadataRevision++
	if err := l.Apply(l.Begin(), u); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Current(); err == nil {
		t.Fatal("metadata replacement retained native stream authority")
	}
	u.View.MetadataRevision--
	if err := l.Apply(l.Begin(), u); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Current(); err == nil {
		t.Fatal("later policy revived a removed native guard")
	}
	g.Close()
	if _, err := (*NativeGuard)(nil).Current(); err == nil {
		t.Fatal("nil native guard allowed use")
	}
}

func TestPolicyNativeCannotBorrowRequestGuard(t *testing.T) {
	l, _, _, _ := nativeGuardFixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	permission := admission(t, l, key, "first", time.Now().Add(time.Minute))
	request, err := l.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	if _, ok := any(request).(interface{ Current() (time.Time, error) }); ok {
		t.Fatal("request guard exposed native stream use")
	}
	if g, err := l.BindNative(permission, netip.MustParseAddr("192.0.2.1"), 5, nil, func() {}); err == nil || g != nil {
		t.Fatal("a valid HTTP bearer minted native stream permission")
	}
}
