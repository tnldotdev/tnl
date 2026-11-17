package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type certificateRecoveryControl struct {
	*lifecycleControl
	store     CertificateStore
	create    func([]byte, string) (controlv1.ServiceCertificateIssuance, error)
	get       func(context.Context, string) (controlv1.ServiceCertificateIssuance, error)
	installed func(string, time.Time) error
}

func (c *certificateRecoveryControl) GetServiceCertificateIssuance(ctx context.Context, service, run, issuance string, token credentials.ServiceRunToken) (controlv1.ServiceCertificateIssuance, error) {
	if service != c.prep.ServiceId || run != c.prep.ServiceRunId || token.String() != c.setup.RunToken {
		return controlv1.ServiceCertificateIssuance{}, ErrPrivateStream
	}
	if c.get != nil {
		return c.get(ctx, issuance)
	}
	return c.lifecycleControl.GetServiceCertificateIssuance(ctx, service, run, issuance, token)
}

func (c *certificateRecoveryControl) CreateServiceCertificateIssuance(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken, csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
	if service != c.prep.ServiceId || run != c.prep.ServiceRunId || number != c.prep.RunNumber || token.String() != c.setup.RunToken {
		return controlv1.ServiceCertificateIssuance{}, ErrPrivateStream
	}
	if c.create != nil {
		return c.create(csr, key)
	}
	issued, err := c.lifecycleControl.CreateServiceCertificateIssuance(ctx, service, run, number, token, csr, key)
	issued.Id = "test-issuance-" + key
	return issued, err
}

func (c *certificateRecoveryControl) MarkServiceCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, notAfter time.Time, token credentials.ServiceRunToken) error {
	if service != c.prep.ServiceId || run != c.prep.ServiceRunId || number != c.prep.RunNumber || token.String() != c.setup.RunToken {
		return ErrPrivateStream
	}
	if c.installed != nil {
		return c.installed(issuance, notAfter)
	}
	return c.lifecycleControl.MarkServiceCertificateInstalled(ctx, service, run, number, issuance, notAfter, token)
}

func certificateRecoveryFixture(t *testing.T) (Certificates, *certificateRecoveryControl, *Prepared) {
	t.Helper()
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := newManagedPrepared(control.prep, approved, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := cfg.State.CertificatesForPublisher(control.prep.TeamId, cfg.PublisherIdentityID, *control.prep.CertificatePlan)
	if err != nil {
		t.Fatal(err)
	}
	recovery := &certificateRecoveryControl{lifecycleControl: control, store: cfg.State}
	return Certificates{Control: recovery, Cache: cache, ServiceID: control.prep.ServiceId,
		RunID: control.prep.ServiceRunId, RunNumber: control.prep.RunNumber,
		PublisherIdentityID: cfg.PublisherIdentityID, Token: credentials.ServiceRunToken(control.setup.RunToken),
		Hostname: control.prep.Hostname, Plan: *control.prep.CertificatePlan, Install: prepared.installManagedCertificate}, recovery, prepared
}

func TestServiceCertificateRecoversCreateAndInstallResponseLoss(t *testing.T) {
	for _, phase := range []string{"create", "installed"} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/committed=%t", phase, committed), func(t *testing.T) {
				certificates, control, prepared := certificateRecoveryFixture(t)
				var issued controlv1.ServiceCertificateIssuance
				var firstCSR []byte
				var firstKey string
				lost, acknowledged := false, false
				control.create = func(csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
					if firstCSR == nil {
						firstCSR, firstKey = bytes.Clone(csr), key
					} else if !bytes.Equal(firstCSR, csr) || firstKey != key {
						t.Error("response-loss recovery changed the CSR or idempotency key")
					}
					if phase == "create" && !lost && !committed {
						lost = true
						return controlv1.ServiceCertificateIssuance{}, clientcontrol.ErrUnavailable
					}
					if issued.Id == "" {
						var err error
						issued, err = control.lifecycleControl.CreateServiceCertificateIssuance(t.Context(),
							certificates.ServiceID, certificates.RunID, certificates.RunNumber, certificates.Token, csr, key)
						if err != nil {
							return issued, err
						}
					}
					if phase == "create" && !lost {
						lost = true
						return controlv1.ServiceCertificateIssuance{}, clientcontrol.ErrUnavailable
					}
					return issued, nil
				}
				control.installed = func(id string, notAfter time.Time) error {
					staged, found, err := certificates.Cache.Staged(t.Context(), certificates.Hostname)
					if err != nil || !found || staged.IssuanceID != id || !staged.Certificate.Leaf.NotAfter.Equal(notAfter) {
						t.Error("installation acknowledgment preceded durable matching material", found, err)
					}
					if _, err := prepared.currentCertificate(); err == nil {
						t.Error("unacknowledged initial certificate reached the serving owner")
					}
					if phase == "installed" && !lost {
						lost, acknowledged = true, committed
						return clientcontrol.ErrUnavailable
					}
					acknowledged = true
					return nil
				}
				if _, err := certificates.advance(t.Context(), true); !errors.Is(err, clientcontrol.ErrUnavailable) || !lost {
					t.Fatal("response-loss boundary was not reached", err)
				}
				if _, found, err := certificates.Cache.Current(t.Context(), certificates.Hostname); err != nil || found {
					t.Fatal("lost response promoted unacknowledged material", found, err)
				}
				// a new cache handle recovers durable pending or staged state,
				// rather than depending on an in-memory issuance attempt.
				cache, err := control.store.CertificatesForPublisher(control.prep.TeamId, certificates.PublisherIdentityID, certificates.Plan)
				if err != nil {
					t.Fatal(err)
				}
				certificates.Cache = cache
				material, err := certificates.advance(t.Context(), true)
				if err != nil || !acknowledged || material.IssuanceID != issued.Id {
					t.Fatal("the exact certificate transaction did not recover", acknowledged, err)
				}
				if err := certificates.Install(material.Certificate); err != nil {
					t.Fatal(err)
				}
				current, err := prepared.currentCertificate()
				if err != nil || !bytes.Equal(current.Certificate[0], material.Certificate.Certificate[0]) {
					t.Fatal("acknowledged certificate was not available to its serving owner", err)
				}
			})
		}
	}
}

func TestServiceCertificateLostRenewalAcknowledgmentPreservesCurrent(t *testing.T) {
	for _, failure := range []error{clientcontrol.ErrUnavailable, clientcontrol.ErrStatusConflict, context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				certificates, control, prepared := certificateRecoveryFixture(t)
				initial, err := certificates.advance(t.Context(), true)
				if err != nil {
					t.Fatal(err)
				}
				if err := certificates.Install(initial.Certificate); err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Until(initial.RenewAt))
				control.installed = func(string, time.Time) error { return failure }
				if _, err := certificates.advance(t.Context(), false); !errors.Is(err, failure) {
					t.Fatal("renewal lost the installation failure", err)
				}
				current, found, err := certificates.Cache.Current(t.Context(), certificates.Hostname)
				if err != nil || !found || current.IssuanceID != initial.IssuanceID {
					t.Fatal("unacknowledged renewal displaced durable current material", found, err)
				}
				serving, err := prepared.currentCertificate()
				if err != nil || !bytes.Equal(serving.Certificate[0], initial.Certificate.Certificate[0]) {
					t.Fatal("unacknowledged renewal displaced the serving certificate", err)
				}
				staged, found, err := certificates.Cache.Staged(t.Context(), certificates.Hostname)
				if err != nil || !found || staged.IssuanceID == initial.IssuanceID {
					t.Fatal("renewal lost its recoverable staged material", found, err)
				}
				if bytes.Equal(staged.Certificate.Leaf.RawSubjectPublicKeyInfo, initial.Certificate.Leaf.RawSubjectPublicKeyInfo) {
					t.Fatal("renewal reused the current application key")
				}
				control.create = func([]byte, string) (controlv1.ServiceCertificateIssuance, error) {
					return controlv1.ServiceCertificateIssuance{}, errors.New("staged renewal requested another issuance")
				}
				control.installed = nil
				recovered, err := certificates.advance(t.Context(), false)
				if err != nil || recovered.IssuanceID != staged.IssuanceID {
					t.Fatal("staged renewal did not recover", err)
				}
				if err := certificates.Install(recovered.Certificate); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestServiceCertificateCachedMaterialAcknowledgesEachRun(t *testing.T) {
	certificates, control, _ := certificateRecoveryFixture(t)
	initial, err := certificates.advance(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	control.create = func([]byte, string) (controlv1.ServiceCertificateIssuance, error) {
		return controlv1.ServiceCertificateIssuance{}, errors.New("compatible cached material requested another issuance")
	}
	acknowledgments := 0
	control.installed = func(id string, notAfter time.Time) error {
		if id != initial.IssuanceID || !notAfter.Equal(initial.Certificate.Leaf.NotAfter) {
			t.Error("new run acknowledged different cached material")
		}
		acknowledgments++
		return nil
	}
	for range 2 {
		id, err := opaqueid.New(opaqueid.ServiceRunPrefix)
		if err != nil {
			t.Fatal(err)
		}
		control.prep.ServiceRunId, certificates.RunID = id, id
		control.prep.RunNumber++
		certificates.RunNumber = control.prep.RunNumber
		material, err := certificates.advance(t.Context(), true)
		if err != nil || material.IssuanceID != initial.IssuanceID {
			t.Fatal("new run failed to acknowledge compatible cached material", err)
		}
	}
	if acknowledgments != 2 {
		t.Fatal("cached certificate skipped a run's installation acknowledgment", acknowledgments)
	}
}

func TestServiceCertificatePendingPollingKeepsOriginalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		certificates, control, prepared := certificateRecoveryFixture(t)
		var issued controlv1.ServiceCertificateIssuance
		var firstCSR []byte
		var firstKey string
		creates, polls, acknowledgments := 0, 0, 0
		started := time.Now()
		deadline := started.Add(7 * time.Second)
		pending := func() controlv1.ServiceCertificateIssuance {
			result := issued
			result.State, result.CertificatePem, result.NotBefore, result.NotAfter = controlv1.CertificateIssuanceStatePending, nil, nil, nil
			result.RetryAt = new(time.Now().Add(3 * time.Second))
			return result
		}
		control.create = func(csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
			creates++
			firstCSR, firstKey = bytes.Clone(csr), key
			var err error
			issued, err = certificateFixtureIssuance(control.lifecycleControl, csr, nil)
			return pending(), err
		}
		control.get = func(ctx context.Context, id string) (controlv1.ServiceCertificateIssuance, error) {
			polls++
			if until, ok := ctx.Deadline(); !ok || !until.Equal(deadline) || id != issued.Id ||
				time.Since(started) != time.Duration(polls)*3*time.Second {
				t.Error("poll reset its original deadline, order, or retry delay", polls, until, id)
			}
			return pending(), nil
		}
		control.installed = func(string, time.Time) error { acknowledgments++; return nil }
		ctx, cancel := context.WithDeadline(t.Context(), deadline)
		defer cancel()
		if err := certificates.Maintain(ctx); !errors.Is(err, context.DeadlineExceeded) || creates != 1 || polls != 2 ||
			acknowledgments != 0 || !time.Now().Equal(deadline) {
			t.Fatal("pending issuance escaped its original budget or spun", creates, polls, acknowledgments, err)
		}
		recovered, err := certificates.Cache.Pending(t.Context(), certificates.Hostname)
		if err != nil || !bytes.Equal(firstCSR, recovered.CSRDER) || firstKey == "" {
			t.Fatal("pending polling replaced its recoverable CSR", err)
		}
		certificateAssertNoMaterial(t, certificates, prepared)
		lock, err := certificates.Cache.Lock(t.Context())
		if err != nil {
			t.Fatal("pending deadline retained the issuance lock", err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestServiceCertificateRetryAtIsNotBeforePolling(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		certificates, control, prepared := certificateRecoveryFixture(t)
		started := time.Now()
		deadline := started.Add(65 * time.Second)
		var issued controlv1.ServiceCertificateIssuance
		creates, polls, acknowledgments := 0, 0, 0
		pending := func() controlv1.ServiceCertificateIssuance {
			result := issued
			result.State, result.CertificatePem, result.NotBefore, result.NotAfter = controlv1.CertificateIssuanceStatePending, nil, nil, nil
			result.RetryAt = new(time.Now().Add(time.Minute))
			return result
		}
		control.create = func(csr []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
			creates++
			var err error
			issued, err = certificateFixtureIssuance(control.lifecycleControl, csr, nil)
			return pending(), err
		}
		control.get = func(ctx context.Context, id string) (controlv1.ServiceCertificateIssuance, error) {
			polls++
			if elapsed := time.Since(started); elapsed != time.Minute {
				t.Error("polled before the advertised not-before time", elapsed)
			}
			if until, ok := ctx.Deadline(); !ok || !until.Equal(deadline) || id != issued.Id {
				t.Error("poll changed the original deadline or issuance", until, id)
			}
			return pending(), nil
		}
		control.installed = func(string, time.Time) error { acknowledgments++; return nil }
		ctx, cancel := context.WithDeadline(t.Context(), deadline)
		defer cancel()
		if err := certificates.Maintain(ctx); !errors.Is(err, context.DeadlineExceeded) ||
			creates != 1 || polls != 1 || acknowledgments != 0 || !time.Now().Equal(deadline) {
			t.Fatal("not-before polling changed the owner budget or repeated pending work", creates, polls, acknowledgments, err)
		}
		certificateAssertNoMaterial(t, certificates, prepared)
		lock, err := certificates.Cache.Lock(t.Context())
		if err != nil {
			t.Fatal("canceled poll retained its issuance lock", err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestServiceCertificateUsableMaterialDoesNotWaitForCleanupRetryAt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		certificates, control, prepared := certificateRecoveryFixture(t)
		started := time.Now()
		acknowledgments, polls := 0, 0
		control.create = func(csr []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
			issued, err := certificateFixtureIssuance(control.lifecycleControl, csr, nil)
			issued.RetryAt = new(started.Add(time.Minute))
			return issued, err
		}
		control.get = func(context.Context, string) (controlv1.ServiceCertificateIssuance, error) {
			polls++
			return controlv1.ServiceCertificateIssuance{}, errors.New("installable material did not need polling")
		}
		control.installed = func(string, time.Time) error {
			acknowledgments++
			return nil
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		certificates.Install = func(certificate tls.Certificate) error {
			err := prepared.installManagedCertificate(certificate)
			cancel()
			return err
		}
		if err := certificates.Maintain(ctx); !errors.Is(err, context.Canceled) ||
			acknowledgments != 1 || polls != 0 || !time.Now().Equal(started) {
			t.Fatal("usable material waited for cleanup polling instead of exact acknowledgment and installation", acknowledgments, polls, err)
		}
		current, found, err := certificates.Cache.Current(t.Context(), certificates.Hostname)
		if err != nil || !found {
			t.Fatal("acknowledged material was not durably promoted", found, err)
		}
		serving, err := prepared.currentCertificate()
		if err != nil || !bytes.Equal(serving.Certificate[0], current.Certificate.Certificate[0]) {
			t.Fatal("usable acknowledged certificate was unavailable for visitor TLS", err)
		}
	})
}

func TestServiceCertificateTerminalFailureRetriesOnlyOnce(t *testing.T) {
	for _, terminal := range []controlv1.CertificateIssuanceState{controlv1.CertificateIssuanceStateFailed, controlv1.CertificateIssuanceStateCanceled} {
		t.Run(string(terminal), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				certificates, control, prepared := certificateRecoveryFixture(t)
				var previousCSR []byte
				var previousKey string
				creates, acknowledgments := 0, 0
				control.create = func(csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
					creates++
					if creates > 1 && (bytes.Equal(previousCSR, csr) || previousKey == key) {
						t.Error("terminal retry reused its failed key, CSR, or idempotency key")
					}
					previousCSR, previousKey = bytes.Clone(csr), key
					issued, err := certificateFixtureIssuance(control.lifecycleControl, csr, nil)
					issued.State, issued.CertificatePem, issued.NotBefore, issued.NotAfter = terminal, nil, nil, nil
					return issued, err
				}
				control.installed = func(string, time.Time) error { acknowledgments++; return nil }
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				if err := certificates.Maintain(ctx); !errors.Is(err, errManagedIssuanceFailed) ||
					errors.Is(err, context.DeadlineExceeded) || creates != 2 || acknowledgments != 0 {
					t.Fatal("initial terminal issuance did not stop after its one fresh attempt", creates, acknowledgments, err)
				}
				certificateAssertNoMaterial(t, certificates, prepared)
			})
		})
	}
}

func TestServiceCertificateTerminalOrderAfterLostResponseRotatesFailedKey(t *testing.T) {
	for _, terminal := range []controlv1.CertificateIssuanceState{controlv1.CertificateIssuanceStateFailed, controlv1.CertificateIssuanceStateCanceled} {
		t.Run(string(terminal), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				certificates, control, prepared := certificateRecoveryFixture(t)
				var originalCSR []byte
				var originalKey string
				var original controlv1.ServiceCertificateIssuance
				creates, acknowledgments := 0, 0
				control.create = func(csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
					creates++
					if creates == 1 {
						originalCSR, originalKey = bytes.Clone(csr), key
						var err error
						original, err = certificateFixtureIssuance(control.lifecycleControl, csr, nil)
						if err != nil {
							return original, err
						}
						original.State, original.CertificatePem, original.NotBefore, original.NotAfter = terminal, nil, nil, nil
						return controlv1.ServiceCertificateIssuance{}, clientcontrol.ErrUnavailable
					}
					if creates == 2 {
						if !bytes.Equal(originalCSR, csr) || originalKey != key {
							t.Error("uncertain create replaced the original certificate attempt")
						}
						return original, nil
					}
					if bytes.Equal(originalCSR, csr) || originalKey == key {
						t.Error("terminal response did not rotate its failed CSR/idempotency key")
					}
					failed, err := x509.ParseCertificateRequest(originalCSR)
					replacement, replacementErr := x509.ParseCertificateRequest(csr)
					if err != nil || replacementErr != nil || bytes.Equal(failed.RawSubjectPublicKeyInfo, replacement.RawSubjectPublicKeyInfo) {
						t.Error("terminal response retained its failed application key", err, replacementErr)
					}
					issued, err := certificateFixtureIssuance(control.lifecycleControl, csr, nil)
					issued.Id = "replacement-certificate-order"
					return issued, err
				}
				control.installed = func(id string, _ time.Time) error {
					acknowledgments++
					if id != "replacement-certificate-order" {
						t.Error("terminal order was acknowledged")
					}
					return nil
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				certificates.Install = func(certificate tls.Certificate) error {
					err := prepared.installManagedCertificate(certificate)
					cancel()
					return err
				}
				if err := certificates.Maintain(ctx); !errors.Is(err, context.Canceled) || creates != 3 || acknowledgments != 1 {
					t.Fatal("terminal response-loss recovery was not exact and bounded", creates, acknowledgments, err)
				}
				current, found, err := certificates.Cache.Current(t.Context(), certificates.Hostname)
				if err != nil || !found || current.IssuanceID != "replacement-certificate-order" {
					t.Fatal("replacement did not become the durable current certificate", found, err)
				}
				if serving, err := prepared.currentCertificate(); err != nil || !bytes.Equal(serving.Certificate[0], current.Certificate.Certificate[0]) {
					t.Fatal("terminal order displaced the recovered serving material", err)
				}
			})
		})
	}
}

func TestServiceCertificateCacheDoesNotCrossApprovedPlans(t *testing.T) {
	for _, boundary := range []string{"cache key", "scope", "identifiers"} {
		t.Run(boundary, func(t *testing.T) {
			certificates, control, _ := certificateRecoveryFixture(t)
			originalCache := certificates.Cache
			initial, err := certificates.advance(t.Context(), true)
			if err != nil {
				t.Fatal(err)
			}
			changed := certificates.Plan
			switch boundary {
			case "cache key":
				changed.CacheKey = "different-cache-key"
			case "scope":
				changed.Scope = "different-scope"
			case "identifiers":
				changed.Identifiers = []string{certificates.Hostname, "*." + certificates.Hostname}
			}
			certificates.Plan, control.prep.CertificatePlan = changed, &changed
			certificates.Cache, err = control.store.CertificatesForPublisher(control.prep.TeamId, certificates.PublisherIdentityID, changed)
			if err != nil {
				t.Fatal(err)
			}
			creates, acknowledgments := 0, 0
			control.create = func(csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
				creates++
				issued, err := certificateFixtureIssuance(control.lifecycleControl, csr, nil)
				issued.Id = "replacement-" + key
				return issued, err
			}
			control.installed = func(id string, _ time.Time) error {
				acknowledgments++
				if id == initial.IssuanceID {
					t.Error("changed plan acknowledged incompatible cached material")
				}
				return nil
			}
			material, err := certificates.advance(t.Context(), true)
			if err != nil || creates != 1 || acknowledgments != 1 || material.IssuanceID == initial.IssuanceID ||
				bytes.Equal(material.Certificate.Leaf.RawSubjectPublicKeyInfo, initial.Certificate.Leaf.RawSubjectPublicKeyInfo) {
				t.Fatal("changed plan reused an incompatible certificate or key", creates, acknowledgments, err)
			}
			retained, found, err := originalCache.Current(t.Context(), certificates.Hostname)
			if err != nil || !found || retained.IssuanceID != initial.IssuanceID {
				t.Fatal("new plan destroyed another plan's durable material", found, err)
			}
		})
	}
}

func TestServiceCertificateRecreatedServiceReusesCompatibleCache(t *testing.T) {
	certificates, control, _ := certificateRecoveryFixture(t)
	initial, err := certificates.advance(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	service, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	run, err := opaqueid.New(opaqueid.ServiceRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	certificates.ServiceID, control.prep.ServiceId = service, service
	certificates.RunID, control.prep.ServiceRunId = run, run
	certificates.RunNumber, control.prep.RunNumber = 1, 1
	control.create = func([]byte, string) (controlv1.ServiceCertificateIssuance, error) {
		t.Error("recreated service requested another compatible namespace certificate")
		return controlv1.ServiceCertificateIssuance{}, errors.New("unexpected issuance")
	}
	acknowledgments := 0
	control.installed = func(id string, notAfter time.Time) error {
		acknowledgments++
		if id != initial.IssuanceID || !notAfter.Equal(initial.Certificate.Leaf.NotAfter) {
			t.Error("recreated service acknowledged different compatible material")
		}
		return nil
	}
	// reopen the protected cache rather than retaining an in-memory transaction.
	certificates.Cache, err = control.store.CertificatesForPublisher(control.prep.TeamId, certificates.PublisherIdentityID, certificates.Plan)
	if err != nil {
		t.Fatal(err)
	}
	material, err := certificates.advance(t.Context(), true)
	if err != nil || acknowledgments != 1 || material.IssuanceID != initial.IssuanceID ||
		!bytes.Equal(material.Certificate.Certificate[0], initial.Certificate.Certificate[0]) {
		t.Fatal("recreated service failed to acknowledge compatible cached material", acknowledgments, err)
	}
}
