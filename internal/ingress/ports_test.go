package ingress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestPoolInventoryRetriesStartupButNotAuthorizationFailures(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/v1/ingress-pools/ingress-a/ports" {
					t.Error("inventory requested the wrong pool", r.URL.Path)
				}
				if calls.Add(1) <= 2 {
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"code":"internal","detail":"not ready"}`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[{"first":25000,"last":25010}]`))
			}))
			defer server.Close()
			generated, err := ingressv1.NewClientWithResponses(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewHTTPControlClient(generated)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			inventory, err := client.ReadIngressPoolPorts(ctx, "ingress-a", time.Nanosecond)
			if status == http.StatusUnauthorized {
				if err == nil || calls.Load() != 1 {
					t.Fatal("authorization failure was retried", err, calls.Load())
				}
			} else if err != nil || calls.Load() != 3 || !inventory.Contains(25000) || inventory.Contains(25011) {
				t.Fatal("startup inventory retry", err, calls.Load())
			}
		})
	}
}

func TestPoolInventoryCancellationInterruptsRetryWait(t *testing.T) {
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	generated, err := ingressv1.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewHTTPControlClient(generated)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.ReadIngressPoolPorts(ctx, "ingress-a", time.Hour)
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("canceled startup did not join", err)
	}
}
