package adhoc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPrepareReturnsUncertainOwnershipBeforeCallerCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := &allocationControl{}
		native := allocationNative(t, control)
		options := allocationOptions(native)
		expiry := time.Now().Add(time.Hour)
		options.ExpiresAt, options.IP = &expiry, []string{"192.0.2.0/24"}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var bodies [][]byte
		var saved controlv1.Service
		control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
			encoded, _ := json.Marshal(body)
			bodies = append(bodies, encoded)
			if len(bodies) == 1 {
				saved = allocatedService(body)
				cancel()
				return controlv1.Service{}, io.ErrUnexpectedEOF
			}
			return saved, nil
		}
		control.read = func() (controlv1.Service, error) {
			t.Error("cleanup selected publication instead of allocation ownership")
			return controlv1.Service{}, errors.New("unexpected selection")
		}
		var deleted []string
		control.remove = func(id string) error { deleted = append(deleted, id); return nil }
		prepared, err := Prepare(ctx, options)
		if prepared == nil || !errors.Is(err, context.Canceled) || !errors.Is(err, io.ErrUnexpectedEOF) ||
			prepared.Service.Id != "" || prepared.Config.Control != nil || len(bodies) != 1 || len(deleted) != 0 {
			t.Fatal("uncertain preparation hid its owner or performed caller cleanup", prepared, err, len(bodies), deleted)
		}
		expiry = expiry.Add(time.Hour)
		options.IP[0] = "198.51.100.0/24"
		cleanup, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		if err := prepared.Cleanup(cleanup); err != nil {
			t.Fatal(err)
		}
		if err := prepared.Cleanup(cleanup); err != nil {
			t.Fatal("confirmed cleanup was not terminal", err)
		}
		if len(bodies) != 2 || string(bodies[0]) != string(bodies[1]) || !reflect.DeepEqual(deleted, []string{saved.Id}) {
			t.Fatal("caller cleanup changed the immutable request or exact deletion", len(bodies), deleted)
		}
	})
}

func TestPreparedServiceSnapshotCannotChangePublicationOrCleanup(t *testing.T) {
	control := &allocationControl{}
	native := allocationNative(t, control)
	options := allocationOptions(native)
	options.Target = "https://target.example.test:443"
	expiry := time.Now().Add(time.Hour)
	options.ExpiresAt = &expiry
	options.OnAllocated = func(controlv1.Service) error { t.Error("preparation invoked Run's application callback"); return nil }
	options.Ready = func() error { t.Error("preparation started publication"); return nil }
	var saved controlv1.Service
	control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
		saved = allocatedService(body)
		return saved, nil
	}
	control.read = func() (controlv1.Service, error) { return saved, nil }
	var deleted []string
	control.remove = func(id string) error { deleted = append(deleted, id); return nil }
	prepared, err := Prepare(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Config.ServiceID != saved.Id || prepared.Config.State != options.State || prepared.Config.Control == native ||
		prepared.Publisher() != prepared.Config.Control ||
		prepared.Config.PublisherGrantID != native.PublisherGrantID() || prepared.Config.PublisherKeyID != native.PublisherKeyID() {
		t.Fatal("preparation did not retain the real forked publisher and borrowed state")
	}
	prepared.Service.Id = "fabricated"
	prepared.Service.Endpoint.Hostname = "changed.example.test"
	prepared.Service.TargetTls.Hostname = "changed.example.test"
	*prepared.Service.ExpiresAt = expiry.Add(time.Hour)
	if prepared.Config.ServiceID != saved.Id || prepared.Config.Metadata.TargetTls.Hostname != "target.example.test" ||
		!prepared.request.ExpiresAt.Equal(expiry) || prepared.request.Configuration.TargetTls.Hostname != "target.example.test" {
		t.Fatal("service snapshot mutated publication or private recovery facts")
	}
	cleanup, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := prepared.Cleanup(cleanup); err != nil || !reflect.DeepEqual(deleted, []string{saved.Id}) {
		t.Fatal("snapshot mutation changed cleanup ownership", err, deleted)
	}
}

func TestPreparePreservesExplicitBudgetWithoutRequiringOmittedDefaults(t *testing.T) {
	control := &allocationControl{}
	native := allocationNative(t, control)
	options := allocationOptions(native)
	options.Limits = applicationlimits.Limits{Requests: 7, RateRequests: 3, RatePer: 4 * time.Second}
	expires := time.Now().Add(time.Hour)
	var saved controlv1.Service
	control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
		if body.ExpiresAt != nil || body.Configuration.Http.Limits.Concurrency != nil || body.Configuration.Http.Limits.Rate.Burst != nil {
			t.Fatal("preparation invented an expiry or explicit default")
		}
		saved = allocatedService(body)
		saved.ExpiresAt = &expires
		saved.HttpLimits = &controlv1.ProjectHTTPApplicationLimits{Total: new(7), Concurrency: new(2),
			Rate: &controlv1.ProjectApplicationRate{Count: 3, Per: "4s", Burst: new(5)}}
		return saved, nil
	}
	control.read = func() (controlv1.Service, error) { return saved, nil }
	control.remove = func(id string) error {
		if id != saved.Id {
			t.Fatal("server-approved limits changed exact cleanup")
		}
		return nil
	}
	prepared, err := Prepare(t.Context(), options)
	if err != nil {
		t.Fatal("omitted defaults rejected server-approved ceilings", err)
	}
	if prepared.Service.ExpiresAt == nil || !prepared.Service.ExpiresAt.Equal(expires) || prepared.request.ExpiresAt != nil {
		t.Fatal("server expiry was lost or substituted into the original declaration")
	}
	cleanup, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := prepared.Cleanup(cleanup); err != nil {
		t.Fatal(err)
	}
}
