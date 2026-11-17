package ingress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type publicAdmissionStore struct {
	publicServiceStore
	admit func(context.Context, controlstate.IngressLeaseIdentity, string, string, int, netip.Addr, time.Time, ...controlstate.ServiceRunCursor) (controlstate.PublicServiceVisitorAdmission, error)
}

func (s publicAdmissionStore) AdmitPublicServiceVisitor(ctx context.Context, lease controlstate.IngressLeaseIdentity, pool, visitor string, port int, source netip.Addr, now time.Time, cursor ...controlstate.ServiceRunCursor) (controlstate.PublicServiceVisitorAdmission, error) {
	return s.admit(ctx, lease, pool, visitor, port, source, now, cursor...)
}

func TestPublicServiceAdmissionCursorMatchesDirectAndHTTP(t *testing.T) {
	now := time.Now().UTC()
	serviceID := "svc_" + strings.Repeat("S", 22)
	start := ingressv1.ServiceRunReference{ServiceId: serviceID, ServiceRunId: "srun_" + strings.Repeat("A", 22), RunNumber: 5}
	after := ingressv1.ServiceRunReference{ServiceId: serviceID, ServiceRunId: "srun_" + strings.Repeat("B", 22), RunNumber: 12}
	base := ingressv1.PublicServiceVisitorClaim{
		IngressRunId: "process", IngressLeaseRevision: 4, IngressPoolId: "pool",
		DestinationPort: 25443, ObservedSourceIp: "192.0.2.4",
		VisitorConnectionId: "vc_" + strings.Repeat("V", 22),
	}
	for _, transport := range []string{"direct", "HTTP"} {
		t.Run(transport, func(t *testing.T) {
			calls := 0
			var got []controlstate.ServiceRunCursor
			store := &ingressStoreStub{publicServiceStore: publicAdmissionStore{admit: func(_ context.Context, lease controlstate.IngressLeaseIdentity, pool, visitor string, port int, source netip.Addr, at time.Time, runs ...controlstate.ServiceRunCursor) (controlstate.PublicServiceVisitorAdmission, error) {
				calls++
				got = append([]controlstate.ServiceRunCursor(nil), runs...)
				if lease.IngressID != "ingress" || lease.IngressRunID != base.IngressRunId || lease.IngressLeaseRevision != 4 ||
					pool != base.IngressPoolId || visitor != base.VisitorConnectionId || port != 25443 ||
					source.String() != base.ObservedSourceIp || !at.Equal(now) {
					t.Error("admission changed the lease, endpoint, source, visitor, or time")
				}
				return controlstate.PublicServiceVisitorAdmission{ServiceID: serviceID, RunID: "srun_" + strings.Repeat("Z", 22),
					RunNumber: 8, ConnectionID: visitor, ExpiresAt: now.Add(time.Second), Traffic: trafficlimits.Default()}, nil
			}}}
			direct, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute, Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			handler := testIngressHandler(t, store, now, nil)
			if transport == "HTTP" {
				unauthenticated := httptest.NewRecorder()
				handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, "/internal/v1/ingresses/ingress/public-services/admit", nil))
				if unauthenticated.Code != http.StatusUnauthorized || calls != 0 {
					t.Fatal("public admission bypassed cluster authentication")
				}
			}
			admit := func(body ingressv1.PublicServiceVisitorClaim) int {
				t.Helper()
				if transport == "HTTP" {
					return serveIngressJSON(t, handler, http.MethodPost, "/internal/v1/ingresses/ingress/public-services/admit", body).Code
				}
				_, err := direct.AdmitPublicServiceVisitor(t.Context(), "ingress", body)
				if err == nil {
					return http.StatusOK
				}
				var problem *serverhttp.ProblemError
				if !errors.As(err, &problem) {
					t.Fatal(err)
				}
				return problem.Status
			}
			for _, cursor := range []*ingressv1.ServiceRunCursor{nil, {Start: start, After: start}, {Start: start, After: after}, {Start: after, After: start}} {
				body := base
				body.RunCursor = cursor
				if status := admit(body); status != http.StatusOK {
					t.Fatal("valid cursor rejected", status)
				}
				var want []controlstate.ServiceRunCursor
				if cursor != nil {
					ref := func(row ingressv1.ServiceRunReference) controlstate.ServiceRunReference {
						return controlstate.ServiceRunReference{ServiceID: row.ServiceId, RunID: row.ServiceRunId, RunNumber: row.RunNumber}
					}
					want = []controlstate.ServiceRunCursor{{Start: ref(cursor.Start), After: ref(cursor.After)}}
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatal("admission changed exact cursor", got, want)
				}
			}
			for name, change := range map[string]func(*ingressv1.PublicServiceVisitorClaim){
				"shared HTTPS": func(b *ingressv1.PublicServiceVisitorClaim) { b.DestinationPort = 443 },
				"source zone":  func(b *ingressv1.PublicServiceVisitorClaim) { b.ObservedSourceIp = "fe80::1%en0" },
				"duplicate ID": func(b *ingressv1.PublicServiceVisitorClaim) {
					b.RunCursor.After.ServiceRunId = start.ServiceRunId
				},
				"duplicate number": func(b *ingressv1.PublicServiceVisitorClaim) { b.RunCursor.After.RunNumber = start.RunNumber },
				"wrong service": func(b *ingressv1.PublicServiceVisitorClaim) {
					b.RunCursor.After.ServiceId = "svc_" + strings.Repeat("T", 22)
				},
				"invalid service": func(b *ingressv1.PublicServiceVisitorClaim) { b.RunCursor.Start.ServiceId = "invalid" },
				"invalid run":     func(b *ingressv1.PublicServiceVisitorClaim) { b.RunCursor.Start.ServiceRunId = "invalid" },
				"invalid number":  func(b *ingressv1.PublicServiceVisitorClaim) { b.RunCursor.Start.RunNumber = 0 },
				"missing start":   func(b *ingressv1.PublicServiceVisitorClaim) { b.RunCursor.Start = ingressv1.ServiceRunReference{} },
				"missing after":   func(b *ingressv1.PublicServiceVisitorClaim) { b.RunCursor.After = ingressv1.ServiceRunReference{} },
			} {
				t.Run(name, func(t *testing.T) {
					body := base
					body.RunCursor = &ingressv1.ServiceRunCursor{Start: start, After: after}
					change(&body)
					before := calls
					if status := admit(body); status != http.StatusBadRequest || calls != before {
						t.Fatal("invalid cursor reached state", status, calls-before)
					}
				})
			}
		})
	}
}
