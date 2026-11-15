package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type nativeAuditFixture struct {
	ServiceControl
	calls        int
	ctx          context.Context
	service, run string
	number       int64
	token        credentials.ServiceRunToken
	batch        serviceaudit.Batch
	err          error
}

func (c *nativeAuditFixture) ReportServiceRunObservations(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken, batch serviceaudit.Batch) error {
	c.calls++
	c.ctx, c.service, c.run, c.number, c.token, c.batch = ctx, service, run, number, token, batch
	return c.err
}

func TestConnectorAuditForwardingRetainsSelectedServiceAndRunCredential(t *testing.T) {
	n, _ := privateScopeFixture(t)
	c := &nativeAuditFixture{}
	n.NativeControl = NativeControl{Services: c}
	service := n.selectedServiceID
	run, err := opaqueid.New(opaqueid.ServiceRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	otherRun, err := opaqueid.New(opaqueid.ServiceRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	otherService, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := credentials.NewServiceRunToken()
	if err != nil {
		t.Fatal(err)
	}
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service, ServiceKind: "service", RunID: run, RunNumber: 7,
		EventType: "http.decision", VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", OccurredAt: time.Now(), Outcome: "allowed"}
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{o}}
	expected := serviceaudit.Batch{Events: []serviceaudit.Observation{o}}
	if err := n.ReportServiceRunObservations(t.Context(), service, run, 7, token, batch); err != nil || c.calls != 1 ||
		c.ctx != t.Context() || c.service != service || c.run != run || c.number != 7 || c.token != token ||
		!reflect.DeepEqual(c.batch, expected) || !reflect.DeepEqual(batch, expected) {
		t.Fatal("native changed audit context, exact service/run, credential, or HTTP decision batch", err)
	}
	for _, boundary := range []string{"service", "run", "number", "service-family"} {
		t.Run(boundary, func(t *testing.T) {
			invalid := o
			switch boundary {
			case "service":
				invalid.ServiceID = otherService
			case "run":
				invalid.RunID = otherRun
			case "number":
				invalid.RunNumber++
			case "service-family":
				invalid.ServiceKind = "public_url"
			}
			if err := n.ReportServiceRunObservations(t.Context(), service, run, 7, token, serviceaudit.Batch{Events: []serviceaudit.Observation{o, invalid}}); !errors.Is(err, ErrScope) || c.calls != 1 {
				t.Fatal("audit accepted an event outside the selected service/run/number", err)
			}
		})
	}
	if err := n.ReportServiceRunObservations(t.Context(), otherService, run, 7, token, batch); !errors.Is(err, ErrScope) || c.calls != 1 {
		t.Fatal("audit escaped its selected service", err)
	}
	if err := n.ReportServiceRunObservations(t.Context(), service, run, 7, token, serviceaudit.Batch{}); !errors.Is(err, ErrScope) || c.calls != 1 {
		t.Fatal("empty audit batch reached the control client", err)
	}
	failed := errors.New("audit backend failed")
	c.err = failed
	if err := n.ReportServiceRunObservations(t.Context(), service, run, 7, token, batch); !errors.Is(err, failed) || c.calls != 2 {
		t.Fatal("audit forwarding lost its backend failure", err)
	}
	n.Services = nil
	if err := n.ReportServiceRunObservations(t.Context(), service, run, 7, token, batch); !errors.Is(err, ErrScope) || c.calls != 2 {
		t.Fatal("missing audit capability fell back to a retired client", err)
	}
}
