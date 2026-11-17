package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConcurrentServiceNamespaceCertificateLifecycle(t *testing.T) {
	for _, mode := range []string{"cold", "renew", "renew_expired"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var controls [2]*certificateRecoveryControl
				var configs [2]RunConfig
				var caches [2]*clientstate.CertificateCache
				var prepared [2]*Prepared
				var ready [2]int
				var acknowledged [2]clientstate.Material
				var mu sync.Mutex
				readyEvents := make(chan int, 8)
				pendingOrder := make(chan struct{})
				var pendingStarted sync.Once
				orders := make(map[string]controlv1.ServiceCertificateIssuance)
				requests := make(map[string][]byte)
				nextOrder := 0
				complete := mode != "cold"
				for index := range controls {
					cfg, base := lifecycleFixture(t)
					base.prep.RunToken = base.setup.RunToken
					if index != 0 {
						cfg.State = configs[0].State
						cfg.PublisherIdentityID = configs[0].PublisherIdentityID
						base.prep.TeamId = controls[0].prep.TeamId
						base.prep.PublisherIdentityId = cfg.PublisherIdentityID
					}
					base.prep.Hostname = fmt.Sprintf("app%d.member.example", index)
					base.prep.CertificatePlan = &controlv1.CertificatePlan{CacheKey: "member.example", Scope: "member.example",
						Identifiers: []string{"member.example", "*.member.example"}, ChallengeMethod: controlv1.Dns01}
					control := &certificateRecoveryControl{lifecycleControl: base, store: cfg.State}
					controls[index] = control
					cfg.Control = control
					cfg.HeartbeatInterval, cfg.DrainTime = 10*time.Second, time.Second
					cfg.Connectivity.DisableDirect = true
					unused := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
						return nil, errors.New("certificate fixture must use its claimed slot")
					})
					cfg.RelayQUIC, cfg.RelayTCP = unused, unused
					cfg.Connect = func(_ context.Context, bound *Bound, slot uint8, _ ConnectOptions) (SlotSession, error) {
						mu.Lock()
						prepared[index] = bound.prepared
						mu.Unlock()
						return &heldSlot{stopped: make(chan struct{})}, nil
					}
					cfg.Ready = func() error {
						mu.Lock()
						ready[index]++
						mu.Unlock()
						select {
						case readyEvents <- index:
						default:
							t.Error("publisher repeated readiness more than the fixture can record")
						}
						return nil
					}
					configs[index] = cfg
					var err error
					caches[index], err = cfg.State.CertificatesForPublisher(base.prep.TeamId, cfg.PublisherIdentityID, *base.prep.CertificatePlan)
					if err != nil {
						t.Fatal(err)
					}
					response := func(issued controlv1.ServiceCertificateIssuance) controlv1.ServiceCertificateIssuance {
						if !complete {
							issued.State, issued.CertificatePem, issued.NotBefore, issued.NotAfter = controlv1.CertificateIssuanceStatePending, nil, nil, nil
							issued.RetryAt = new(time.Now().Add(time.Second))
						}
						return issued
					}
					control.create = func(csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
						mu.Lock()
						defer mu.Unlock()
						issued, found := orders[key]
						if !found {
							var err error
							issued, err = certificateFixtureIssuance(base, csr, nil)
							if err != nil {
								return issued, err
							}
							nextOrder++
							issued.Id = fmt.Sprintf("shared-certificate-order-%d", nextOrder)
							orders[key], requests[key] = issued, bytes.Clone(csr)
							if !complete {
								pendingStarted.Do(func() { close(pendingOrder) })
							}
						} else if !bytes.Equal(csr, requests[key]) {
							t.Error("one idempotency key selected a different namespace CSR")
						}
						return response(issued), nil
					}
					control.get = func(_ context.Context, id string) (controlv1.ServiceCertificateIssuance, error) {
						mu.Lock()
						defer mu.Unlock()
						for _, issued := range orders {
							if issued.Id == id {
								return response(issued), nil
							}
						}
						return controlv1.ServiceCertificateIssuance{}, errors.New("poll selected an unknown shared issuance")
					}
					control.installed = func(id string, notAfter time.Time) error {
						material, found, err := caches[index].Staged(t.Context(), base.prep.Hostname)
						if err == nil && !found {
							material, found, err = caches[index].Current(t.Context(), base.prep.Hostname)
						}
						if err != nil || !found || material.IssuanceID != id || !material.Certificate.Leaf.NotAfter.Equal(notAfter) {
							return fmt.Errorf("per-run acknowledgment lost durable matching material: found=%t error=%v", found, err)
						}
						mu.Lock()
						acknowledged[index] = material
						mu.Unlock()
						return nil
					}
				}
				var initial clientstate.Material
				if mode != "cold" {
					first := controls[0]
					certificates := Certificates{Control: first, Cache: caches[0], ServiceID: first.prep.ServiceId,
						RunID: first.prep.ServiceRunId, RunNumber: first.prep.RunNumber, PublisherIdentityID: first.prep.PublisherIdentityId,
						Token: credentials.ServiceRunToken(first.setup.RunToken), Hostname: first.prep.Hostname, Plan: *first.prep.CertificatePlan}
					var err error
					initial, err = certificates.advance(t.Context(), true)
					if err != nil {
						t.Fatal(err)
					}
					orders, requests = make(map[string]controlv1.ServiceCertificateIssuance), make(map[string][]byte)
					acknowledged = [2]clientstate.Material{}
					complete = false
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
				var results [2]error
				var joined [2]chan struct{}
				var wantError error
				for index := range controls {
					joined[index] = make(chan struct{})
					go func() {
						defer close(joined[index])
						results[index] = Publish(ctx, configs[index])
					}()
				}
				defer func() {
					cancel()
					for index := range controls {
						<-joined[index]
						if wantError == nil && results[index] != nil || wantError != nil && !errors.Is(results[index], wantError) {
							t.Error("certificate publication returned a different cause", index, results[index], wantError)
						}
						controls[index].mu.Lock()
						if controls[index].closes != 1 || controls[index].bad != nil {
							t.Error("certificate lifecycle did not close its exact run once", index, controls[index].closes, controls[index].bad)
						}
						controls[index].mu.Unlock()
					}
				}()
				// observe actual cached-certificate readiness before waiting for
				// renewal; certificate installation need not coincide with a tick.
				if mode != "cold" {
					for range controls {
						select {
						case <-readyEvents:
						case <-joined[0]:
							t.Fatal("first publisher stopped before cached-certificate readiness")
						case <-joined[1]:
							t.Fatal("second publisher stopped before cached-certificate readiness")
						}
					}
					synctest.Wait()
					mu.Lock()
					if ready != [2]int{1, 1} {
						t.Error("both publishers did not start on compatible current material", ready)
					}
					mu.Unlock()
				}
				select {
				case <-pendingOrder:
				case <-joined[0]:
					t.Fatal("first publisher stopped before the pending namespace order")
				case <-joined[1]:
					t.Fatal("second publisher stopped before the pending namespace order")
				}
				// both runs must keep heartbeats running while one worker holds
				// the issuance lock across pending polls.
				time.Sleep(21 * time.Second)
				synctest.Wait()
				mu.Lock()
				if len(orders) != 1 {
					t.Error("concurrent publishers created more than one pending namespace order", len(orders))
				}
				for index := range controls {
					if mode == "cold" {
						if ready[index] != 0 || acknowledged[index].IssuanceID != "" {
							t.Error("cold publisher became ready or acknowledged before issuance completed", index)
						}
					} else if acknowledged[index].IssuanceID != initial.IssuanceID {
						t.Error("pending renewal displaced a valid per-run certificate", index)
					}
				}
				mu.Unlock()
				for index, control := range controls {
					control.mu.Lock()
					if control.heartbeats < 2 {
						t.Error("certificate lock or pending issuance stopped run heartbeats", index, control.heartbeats)
					}
					control.mu.Unlock()
				}
				if mode == "renew_expired" {
					wantError = errCertificateExpired
					time.Sleep(time.Until(initial.Certificate.Leaf.NotAfter) - time.Second)
					synctest.Wait()
					for index := range controls {
						if _, err := prepared[index].currentCertificate(); err != nil {
							t.Error("pending renewal stopped a still-valid serving certificate", index, err)
						}
					}
					time.Sleep(time.Second)
					synctest.Wait()
					for index := range controls {
						select {
						case <-joined[index]:
							if !errors.Is(results[index], errCertificateExpired) {
								t.Error("publisher did not retain certificate expiry", index, results[index])
							}
						default:
							t.Error("publisher survived certificate expiry while renewal was pending", index)
						}
						if _, err := prepared[index].currentCertificate(); err == nil {
							t.Error("expired certificate remained available", index)
						}
					}
					lock, err := caches[0].Lock(t.Context())
					if err != nil {
						t.Fatal("expired workers retained the shared issuance lock", err)
					}
					if err := lock.Close(); err != nil {
						t.Fatal(err)
					}
					mu.Lock()
					if len(orders) != 1 || ready != [2]int{1, 1} {
						t.Error("expiry replayed issuance or readiness", len(orders), ready)
					}
					mu.Unlock()
					return
				}
				mu.Lock()
				complete = true
				mu.Unlock()
				time.Sleep(12 * time.Second)
				synctest.Wait()
				mu.Lock()
				defer mu.Unlock()
				if len(orders) != 1 || ready != [2]int{1, 1} || acknowledged[0].IssuanceID == "" ||
					acknowledged[0].IssuanceID != acknowledged[1].IssuanceID ||
					!bytes.Equal(acknowledged[0].Certificate.Certificate[0], acknowledged[1].Certificate.Certificate[0]) {
					t.Error("shared issuance did not converge with exactly one notification per publisher", len(orders), ready)
				}
				for index := range controls {
					current, err := prepared[index].currentCertificate()
					if err != nil || !bytes.Equal(current.Certificate[0], acknowledged[index].Certificate.Certificate[0]) {
						t.Error("publisher did not install its acknowledged shared certificate", index, err)
					}
					if mode != "cold" && err == nil && bytes.Equal(current.Certificate[0], initial.Certificate.Certificate[0]) {
						t.Error("completed renewal retained the old certificate", index)
					}
				}
				if mode != "cold" {
					for _, csr := range requests {
						parsed, err := x509.ParseCertificateRequest(csr)
						if err != nil || bytes.Equal(parsed.RawSubjectPublicKeyInfo, initial.Certificate.Leaf.RawSubjectPublicKeyInfo) {
							t.Error("namespace renewal reused the current application key", err)
						}
					}
				}
			})
		})
	}
}
