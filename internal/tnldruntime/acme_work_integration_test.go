package tnldruntime

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestIntegrationACMEChallengeAcknowledgementDuringWork(t *testing.T) {
	acknowledgementPending := make(chan struct{})
	workerClaimed := make(chan struct{})
	acknowledgementReturned := make(chan struct{})
	release := sync.OnceFunc(func() { close(acknowledgementReturned) })
	defer release()
	var gatedWorker, gatedAcknowledgement atomic.Bool
	var acknowledgementStatus, newOrders atomic.Int64
	configureControlHTTP := func(client *http.Client) {
		base := client.Transport
		client.Transport = splitACMERoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if strings.HasSuffix(request.URL.Path, "/challenge-ready") && gatedAcknowledgement.CompareAndSwap(false, true) {
				close(acknowledgementPending)
				select {
				case <-workerClaimed:
				case <-request.Context().Done():
					_ = request.Body.Close()
					return nil, request.Context().Err()
				}
				response, err := base.RoundTrip(request)
				if response != nil {
					acknowledgementStatus.Store(int64(response.StatusCode))
				}
				// headers arrive after the acknowledgement transaction commits. only
				// then may the worker finish its CA request and try its stale save.
				release()
				return response, err
			}
			return base.RoundTrip(request)
		})
	}
	fixture := newSplitPublishFixtureWithOptions(t, "acknowledgement-race", splitPublishOptions{
		configureControlHTTP: configureControlHTTP,
	}, func(client *http.Client) {
		base := client.Transport
		client.Transport = splitACMERoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPost && request.URL.Path == "/order-plz" {
				newOrders.Add(1)
			}
			if strings.HasPrefix(request.URL.Path, "/my-order/") {
				select {
				case <-acknowledgementPending:
					if gatedWorker.CompareAndSwap(false, true) {
						// the publisher's acknowledgement is waiting, so this
						// worker has claimed a still-presenting authorization.
						close(workerClaimed)
						select {
						case <-acknowledgementReturned:
						case <-request.Context().Done():
							_ = request.Body.Close()
							return nil, request.Context().Err()
						}
					}
				default:
				}
			}
			return base.RoundTrip(request)
		})
	})
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "acknowledged certificate")
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	quic, tcp := fixture.connectors()
	handle := fixture.startPublisher(t, target.URL, quic, tcp)
	ready := fixture.waitReady(t, handle)
	if !gatedWorker.Load() || acknowledgementStatus.Load() != http.StatusOK {
		t.Fatalf("acknowledgement did not overlap claimed work: gated %t, status %d", gatedWorker.Load(), acknowledgementStatus.Load())
	}
	if newOrders.Load() != 1 || integrationRouteOrderCount(t, fixture.inspect, ready.PublicURLID) != 1 {
		t.Fatalf("issuance restarted instead of resuming its original order: ACME new orders %d", newOrders.Load())
	}
	response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/after-acknowledgement", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "acknowledged certificate" {
		t.Fatalf("visitor after acknowledgement race: %s, %q", response.Status, body)
	}
	assertIntegrationPublicURLCertificate(t, response, fixture.identity.hostname)
}
