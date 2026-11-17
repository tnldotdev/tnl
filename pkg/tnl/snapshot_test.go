package tnl

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceAndEndpointSnapshotsAreIndependent(t *testing.T) {
	original := controlv1.Service{Id: "service", DomainId: new("domain"), ExpiresAt: new(time.Now()),
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "service.example.test", Port: 443, Public: true},
		Placement: &controlv1.ServicePlacement{DomainId: new("placement-domain"), Hostname: new("placement-host"),
			WorktreeKey: new("worktree"), WorktreeLabel: new("label")},
		HttpLimits: &controlv1.ProjectHTTPApplicationLimits{Total: new(1), Concurrency: new(2),
			Rate: &controlv1.ProjectApplicationRate{Count: 3, Per: "1s", Burst: new(4)}},
		KubernetesAuth: &controlv1.KubernetesAuth{Cluster: "cluster", Region: "region", Provider: "eks"},
		Source:         &controlv1.LocalServiceSource{Service: "app", ProjectKey: "project"},
		TargetTls:      &controlv1.ServiceTargetTLS{Hostname: "target.example.test", Pem: new("ca"), Digest: "digest"},
		ServiceRunId:   new("run"), RunNumber: new(int64(1))}
	tunnel := &Tunnel{service: cloneService(original)}
	expected, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	first, second := tunnel.Service(), tunnel.Service()
	*first.DomainId, first.Endpoint.Hostname = "changed", "changed.example.test"
	*first.ExpiresAt = first.ExpiresAt.Add(time.Hour)
	*first.Placement.DomainId, *first.Placement.Hostname = "changed", "changed"
	*first.Placement.WorktreeKey, *first.Placement.WorktreeLabel = "changed", "changed"
	*first.HttpLimits.Total, *first.HttpLimits.Concurrency, *first.HttpLimits.Rate.Burst = 99, 99, 99
	first.HttpLimits.Rate.Count = 99
	first.KubernetesAuth.Cluster, first.Source.ProjectKey = "changed", "changed"
	first.TargetTls.Hostname, *first.TargetTls.Pem = "changed", "changed"
	*first.ServiceRunId, *first.RunNumber = "changed", 99
	endpoint := tunnel.Endpoint()
	endpoint.Hostname, endpoint.Port, endpoint.Public = "changed.example.test", 1, false
	for _, value := range []controlv1.Service{original, second, tunnel.Service()} {
		got, err := json.Marshal(value)
		if err != nil || string(got) != string(expected) {
			t.Fatal("mutating a snapshot changed another owner", err, string(got))
		}
	}
	original.Endpoint.Hostname = "caller-mutation.example.test"
	if tunnel.URL() != "https://service.example.test" || tunnel.Endpoint().Port != 443 {
		t.Fatal("snapshot mutation changed the canonical HTTPS address")
	}
	if got := (&Tunnel{}).Endpoint(); got != (controlv1.ServiceEndpoint{}) || (&Tunnel{}).URL() != "" {
		t.Fatal("unallocated tunnel invented an endpoint")
	}
}

func TestPreparedPublisherIdentityExposesNoInternalCapabilities(t *testing.T) {
	identity := reflect.TypeFor[PublisherIdentity]()
	for index := range identity.NumField() {
		if identity.Field(index).IsExported() {
			t.Fatal("publisher identity exposes internal mutable state", identity.Field(index).Name)
		}
	}
	if reflect.TypeFor[*PublisherIdentity]().NumMethod() != 0 {
		t.Fatal("publisher identity exposes its native control or signing capabilities")
	}
}

func TestTunnelCloseBeforeReadyAndConcurrentRepeatedCloseJoinWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		failure := errors.New("joined publication cleanup failed")
		var cancellations atomic.Int32
		tunnel := &Tunnel{done: make(chan struct{}), cancel: func() { cancellations.Add(1); cancel() }}
		finish := make(chan struct{})
		go func() {
			<-ctx.Done()
			<-finish
			tunnel.mu.Lock()
			tunnel.err = errors.Join(context.Canceled, failure)
			tunnel.mu.Unlock()
			close(tunnel.done)
		}()
		closed := make(chan error, 10)
		var workers sync.WaitGroup
		for range 10 {
			workers.Go(func() { closed <- tunnel.Close() })
		}
		<-ctx.Done()
		synctest.Wait()
		select {
		case err := <-closed:
			t.Fatal("Close returned before publication cleanup joined", err)
		default:
		}
		close(finish)
		workers.Wait()
		for range 10 {
			if err := <-closed; !errors.Is(err, failure) {
				t.Fatal("Close discarded an independent joined failure", err)
			}
		}
		if cancellations.Load() != 1 || !errors.Is(tunnel.Wait(), failure) || !errors.Is(tunnel.Close(), failure) {
			t.Fatal("repeated Close changed the one joined result", cancellations.Load())
		}
	})
}
