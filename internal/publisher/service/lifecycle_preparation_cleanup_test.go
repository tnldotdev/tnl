package service

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type preparationCleanupControl struct {
	*lifecycleControl
	prepare       func(context.Context, int, controlv1.ServiceRunPreparation) (controlv1.ServiceRunPreparation, error)
	start         func(context.Context, controlv1.ServiceRunSetup) (controlv1.ServiceRunSetup, error)
	cleanup       error
	keys          []string
	declarations  []controlv1.ServiceRunDeclaration
	starts        int
	closedService string
	closedRun     string
	closedToken   credentials.ServiceRunToken
	closeDeadline time.Time
	recoverUntil  time.Time
}

func (c *preparationCleanupControl) PrepareServiceRun(ctx context.Context, service, key, access string, declaration controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	c.keys = append(c.keys, key)
	c.declarations = append(c.declarations, declaration)
	prepared, err := c.lifecycleControl.PrepareServiceRun(ctx, service, key, access, declaration)
	if err != nil || c.prepare == nil {
		return prepared, err
	}
	return c.prepare(ctx, len(c.keys), prepared)
}

func (c *preparationCleanupControl) StartServiceRun(ctx context.Context, service, run, access string, number int64) (controlv1.ServiceRunSetup, error) {
	c.starts++
	if service != c.prep.ServiceId || run != c.prep.ServiceRunId || access != "scoped-publisher-token" || number != c.prep.RunNumber {
		return controlv1.ServiceRunSetup{}, ErrPrivateStream
	}
	if c.start != nil {
		return c.start(ctx, c.setup)
	}
	return c.setup, nil
}

func (c *preparationCleanupControl) CloseServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken) error {
	c.closedService, c.closedRun, c.closedToken = service, run, token
	c.closeDeadline, _ = ctx.Deadline()
	if ctx.Err() != nil {
		return errors.Join(errors.New("cleanup borrowed a canceled context"), c.cleanup)
	}
	return errors.Join(c.lifecycleControl.CloseServiceRun(ctx, service, run, token), c.cleanup)
}

func preparationCleanupFixture(t *testing.T) (RunConfig, *preparationCleanupControl) {
	t.Helper()
	cfg, base := lifecycleFixture(t)
	control := &preparationCleanupControl{lifecycleControl: base}
	cfg.Control = control
	cfg.Connect = func(context.Context, *Bound, uint8, ConnectOptions) (SlotSession, error) {
		t.Error("failed setup started relay traffic")
		return nil, ErrPrivateStream
	}
	return cfg, control
}

func assertPreparationClosed(t *testing.T, control *preparationCleanupControl) {
	t.Helper()
	if control.closes != 1 || control.closedService != control.prep.ServiceId || control.closedRun != control.prep.ServiceRunId ||
		control.closedToken.String() != control.prep.RunToken || control.bad != nil {
		t.Fatal("cleanup did not close exactly the original preparation", control.closes, control.bad)
	}
	if remaining := time.Until(control.closeDeadline); remaining <= 0 || remaining > 10*time.Second {
		t.Fatal("cleanup did not retain its independent ten-second budget")
	}
}

func TestPreparedRunCleanupBeforeLocalObservation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "observer failure", true: "cancellation"}[canceled], func(t *testing.T) {
			cfg, control := preparationCleanupFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			observerFailure := errors.New("local preparation observation failed")
			cfg.Prepared = func(controlv1.ServiceRunPreparation) error {
				if canceled {
					cancel()
					return context.Cause(ctx)
				}
				return observerFailure
			}
			err := Publish(ctx, cfg)
			want := observerFailure
			if canceled {
				want = context.Canceled
			}
			if !errors.Is(err, want) || control.starts != 0 || len(control.keys) != 1 {
				t.Fatal("observer failure lost its cause or started another mutation", err)
			}
			assertPreparationClosed(t, control)
		})
	}
}

func TestPreparedRunCleanupAfterStartAuthorityFailure(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected", true: "canceled"}[canceled], func(t *testing.T) {
			cfg, control := preparationCleanupFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			cfg.Access = func(context.Context) (string, error) {
				calls++
				if calls == 3 {
					if canceled {
						cancel()
						return "", context.Cause(ctx)
					}
					return "", clientcontrol.ErrUnauthenticated
				}
				return "scoped-publisher-token", nil
			}
			err := Publish(ctx, cfg)
			want := clientcontrol.ErrUnauthenticated
			if canceled {
				want = context.Canceled
			}
			if !errors.Is(err, want) || control.starts != 0 || calls != 3 {
				t.Fatal("cleanup reacquired publisher access or lost its failure", err, calls)
			}
			assertPreparationClosed(t, control)
		})
	}
}

func TestCanceledPrepareRecoversOnlyOriginalInvocation(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled response", true: "lost response"}[lost], func(t *testing.T) {
			cfg, control := preparationCleanupFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			control.prepare = func(attempt context.Context, call int, p controlv1.ServiceRunPreparation) (controlv1.ServiceRunPreparation, error) {
				if call == 1 {
					cancel()
					if lost {
						return controlv1.ServiceRunPreparation{}, io.ErrUnexpectedEOF
					}
					return controlv1.ServiceRunPreparation{}, context.Cause(ctx)
				}
				if attempt.Err() != nil {
					t.Error("recovery used canceled caller authority")
				}
				control.recoverUntil, _ = attempt.Deadline()
				return p, nil
			}
			cfg.Prepared = func(controlv1.ServiceRunPreparation) error {
				t.Error("cleanup published a preparation observation")
				return nil
			}
			err := Publish(ctx, cfg)
			if !errors.Is(err, context.Canceled) || lost && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatal("prepare response loss discarded the operation failure", err)
			}
			if control.starts != 0 || len(control.keys) != 2 || control.keys[0] != control.keys[1] ||
				!reflect.DeepEqual(control.declarations[0], control.declarations[1]) {
				t.Fatal("cleanup selected another invocation, declaration, or Start")
			}
			assertPreparationClosed(t, control)
			if !control.recoverUntil.Equal(control.closeDeadline) {
				t.Fatal("recovery and closure received separate cleanup budgets")
			}
		})
	}
}

func TestCanceledPrepareRetainsIndependentRecoveryFailure(t *testing.T) {
	for _, deniedAtAccess := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepare denied", true: "access denied"}[deniedAtAccess], func(t *testing.T) {
			cfg, control := preparationCleanupFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			control.prepare = func(_ context.Context, call int, _ controlv1.ServiceRunPreparation) (controlv1.ServiceRunPreparation, error) {
				if call == 1 {
					cancel()
					return controlv1.ServiceRunPreparation{}, context.Cause(ctx)
				}
				return controlv1.ServiceRunPreparation{}, clientcontrol.ErrUnauthenticated
			}
			accesses := 0
			cfg.Access = func(context.Context) (string, error) {
				accesses++
				if deniedAtAccess && accesses == 3 {
					return "", clientcontrol.ErrUnauthenticated
				}
				return "scoped-publisher-token", nil
			}
			err := Publish(ctx, cfg)
			if !errors.Is(err, context.Canceled) || !errors.Is(err, clientcontrol.ErrUnauthenticated) ||
				failure.Only(err, context.Canceled) || control.closes != 0 || control.starts != 0 {
				t.Fatal("denied recovery pretended cleanup succeeded or started traffic", err)
			}
		})
	}
}

func TestLostSuccessfulStartClosesWithoutStartingAgain(t *testing.T) {
	cfg, control := preparationCleanupFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	control.start = func(context.Context, controlv1.ServiceRunSetup) (controlv1.ServiceRunSetup, error) {
		cancel()
		return controlv1.ServiceRunSetup{}, io.ErrUnexpectedEOF
	}
	err := Publish(ctx, cfg)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, io.ErrUnexpectedEOF) || control.starts != 1 || len(control.keys) != 1 {
		t.Fatal("uncertain successful Start changed its invocation or lost its failure", err)
	}
	assertPreparationClosed(t, control)
}

func TestMalformedPreparationConfigurationStillClosesExactBinding(t *testing.T) {
	for _, boundary := range []string{"hostname", "expired", "certificate plan", "traffic"} {
		t.Run(boundary, func(t *testing.T) {
			cfg, control := preparationCleanupFixture(t)
			control.prepare = func(_ context.Context, _ int, p controlv1.ServiceRunPreparation) (controlv1.ServiceRunPreparation, error) {
				switch boundary {
				case "hostname":
					p.Hostname = "another.example.test"
				case "expired":
					p.ExpiresAt = time.Now().Add(-time.Second)
				case "certificate plan":
					p.CertificatePlan = nil
				case "traffic":
					p.Traffic.RatePerNs = 0
				}
				return p, nil
			}
			observed := false
			cfg.Prepared = func(controlv1.ServiceRunPreparation) error { observed = true; return nil }
			err := Publish(t.Context(), cfg)
			if !errors.Is(err, ErrPrivateStream) || observed || control.starts != 0 || len(control.keys) != 1 {
				t.Fatal("malformed configuration reached local observation or Start", err)
			}
			assertPreparationClosed(t, control)
		})
	}
}

func TestMalformedPreparationBindingNeverClosesResponseSelectedRun(t *testing.T) {
	for _, boundary := range []string{"service", "publisher", "grant", "key", "invocation", "run", "number", "token", "team", "guest"} {
		t.Run(boundary, func(t *testing.T) {
			cfg, control := preparationCleanupFixture(t)
			control.prepare = func(_ context.Context, _ int, p controlv1.ServiceRunPreparation) (controlv1.ServiceRunPreparation, error) {
				switch boundary {
				case "service":
					p.ServiceId = opaqueid.ServicePrefix + strings.Repeat("S", 22)
				case "publisher":
					p.PublisherIdentityId = opaqueid.PublisherIdentityPrefix + strings.Repeat("P", 22)
				case "grant":
					p.PublisherGrantId = opaqueid.PublisherGrantPrefix + strings.Repeat("G", 22)
				case "key":
					p.PublisherKeyId = opaqueid.PublisherIdentityKeyPrefix + strings.Repeat("K", 22)
				case "invocation":
					p.IdempotencyKey = opaqueid.IdempotencyPrefix + strings.Repeat("I", 22)
				case "run":
					p.ServiceRunId = "invalid"
				case "number":
					p.RunNumber = 0
				case "token":
					p.RunToken = ""
				case "team":
					p.TeamId = "another-team"
				case "guest":
					p.GuestId = "another-guest"
				}
				return p, nil
			}
			cfg.Prepared = func(controlv1.ServiceRunPreparation) error {
				t.Error("malformed binding reached local observation")
				return nil
			}
			err := Publish(t.Context(), cfg)
			if !errors.Is(err, ErrPrivateStream) || control.closes != 0 || control.starts != 0 ||
				len(control.keys) != 2 || control.keys[0] != control.keys[1] {
				t.Fatal("malformed binding closed foreign state or selected a new invocation", err)
			}
		})
	}
}

func TestMalformedStartResponseClosesOnlyPreparation(t *testing.T) {
	for _, boundary := range []string{"service", "run", "number", "token"} {
		t.Run(boundary, func(t *testing.T) {
			cfg, control := preparationCleanupFixture(t)
			control.start = func(_ context.Context, setup controlv1.ServiceRunSetup) (controlv1.ServiceRunSetup, error) {
				switch boundary {
				case "service":
					setup.ServiceId = opaqueid.ServicePrefix + strings.Repeat("S", 22)
				case "run":
					setup.ServiceRunId = opaqueid.ServiceRunPrefix + strings.Repeat("R", 22)
				case "number":
					setup.RunNumber++
				case "token":
					setup.RunToken = "different-opaque-token"
				}
				return setup, nil
			}
			err := Publish(t.Context(), cfg)
			if !errors.Is(err, ErrPrivateStream) || control.starts != 1 || len(control.keys) != 1 {
				t.Fatal("malformed Start response reached serving or another invocation", err)
			}
			assertPreparationClosed(t, control)
		})
	}
}

func TestPreparedRunCleanupRetainsIndependentCloseFailure(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "observer failure", true: "cancellation"}[canceled], func(t *testing.T) {
			cfg, control := preparationCleanupFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			operation := errors.New("independent preparation observer failure")
			cleanup := errors.New("independent preparation close failure")
			control.cleanup = cleanup
			cfg.Prepared = func(controlv1.ServiceRunPreparation) error {
				if canceled {
					cancel()
					return errors.Join(context.Cause(ctx), operation)
				}
				return operation
			}
			err := Publish(ctx, cfg)
			if !errors.Is(err, operation) || !errors.Is(err, cleanup) || canceled && !errors.Is(err, context.Canceled) ||
				failure.Only(err, context.Canceled) || strings.Contains(err.Error(), control.prep.RunToken) {
				t.Fatal("cleanup lost an independent failure or exposed its credential")
			}
			assertPreparationClosed(t, control)
		})
	}
	t.Run("cleanup itself canceled", func(t *testing.T) {
		cfg, control := preparationCleanupFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		control.cleanup = context.Canceled
		cfg.Prepared = func(controlv1.ServiceRunPreparation) error {
			cancel()
			return context.Cause(ctx)
		}
		err := Publish(ctx, cfg)
		if !errors.Is(err, context.Canceled) || !errors.Is(err, errPreparationCleanupCanceled) || failure.Only(err, context.Canceled) {
			t.Fatal("independent cleanup cancellation was mistaken for successful caller stop", err)
		}
		assertPreparationClosed(t, control)
	})
}

func TestAccessCancellationBeforePreparationDoesNotRecoverSpeculatively(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(map[int]string{1: "initial access", 2: "preparation access"}[failAt], func(t *testing.T) {
			cfg, control := preparationCleanupFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			accesses := 0
			cfg.Access = func(context.Context) (string, error) {
				accesses++
				if accesses == failAt {
					cancel()
					return "", context.Cause(ctx)
				}
				return "scoped-publisher-token", nil
			}
			err := Publish(ctx, cfg)
			if !failure.Only(err, context.Canceled) || control.closes != 0 || control.starts != 0 || len(control.keys) != 0 || accesses != failAt {
				t.Fatal("pre-mutation cancellation created or closed a reservation", err)
			}
		})
	}
}

func TestControlResponseRecoveryNormalizesOnlyCancellation(t *testing.T) {
	for _, customCause := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller cancellation", true: "caller cause"}[customCause], func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(context.Canceled)
			cause := error(context.Canceled)
			if customCause {
				cause = errors.New("caller stopped this invocation")
			}
			calls := 0
			err := recoverControlResponse(ctx, time.Time{}, func(context.Context) error {
				calls++
				cancel(cause)
				return &net.OpError{Op: "read", Net: "tcp", Err: context.Canceled}
			})
			if err != cause || calls != 1 || !failure.Only(err, cause) {
				t.Fatal("cancellation-only transport error became an independent failure", err)
			}
		})
	}
}

func TestControlResponseRecoveryRetainsJoinedIndependentFailure(t *testing.T) {
	for _, kind := range []string{"sentinel", "network", "eof"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			independent := errors.New("independent control mutation failure")
			var operation error
			switch kind {
			case "sentinel":
				operation = errors.Join(context.Canceled, independent)
			case "network":
				operation = errors.Join(context.Canceled, &net.OpError{Op: "read", Net: "tcp", Err: independent})
			case "eof":
				operation = io.ErrUnexpectedEOF
			}
			calls := 0
			err := recoverControlResponse(ctx, time.Time{}, func(context.Context) error {
				calls++
				cancel()
				return operation
			})
			if !errors.Is(err, context.Canceled) || calls != 1 || failure.Only(err, context.Canceled) {
				t.Fatal("cancellation hid an independent final-attempt failure", err)
			}
			if kind == "eof" {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal("cancellation discarded the final EOF", err)
				}
			} else if !errors.Is(err, independent) {
				t.Fatal("cancellation discarded the joined cause identity", err)
			}
			if kind == "sentinel" && err != operation {
				t.Fatal("nontransient result was changed during cancellation", err)
			}
		})
	}
}

func TestControlResponseRecoveryRetainsOnlyFinalAttempt(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled final attempt", true: "successful final attempt"}[success], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			previous := errors.New("previous transient failure")
			calls := 0
			err := recoverControlResponse(ctx, time.Time{}, func(context.Context) error {
				calls++
				if calls == 1 {
					return &net.OpError{Op: "read", Net: "tcp", Err: previous}
				}
				cancel()
				if success {
					return nil
				}
				return &net.OpError{Op: "read", Net: "tcp", Err: context.Canceled}
			})
			if calls != 2 || errors.Is(err, previous) {
				t.Fatal("recovery accumulated earlier failed attempts", err, calls)
			}
			if success {
				if err != nil {
					t.Fatal("successful recovery acquired cancellation or retry history", err)
				}
			} else if !failure.Only(err, context.Canceled) {
				t.Fatal("final cancellation-only attempt became a terminal operation failure", err)
			}
		})
	}
}

func TestControlResponseRecoveryPreservesNontransientResult(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	operation := errors.New("definitive control rejection")
	calls := 0
	err := recoverControlResponse(ctx, time.Time{}, func(context.Context) error {
		calls++
		cancel()
		return operation
	})
	if err != operation || calls != 1 {
		t.Fatal("cancellation changed a definitive control response", err)
	}
}

func TestControlResponseRecoveryRetainsFailureAtPreparationDeadline(t *testing.T) {
	outer, cancel := context.WithCancel(t.Context())
	defer cancel()
	independent := errors.New("independent failure at the preparation deadline")
	calls := 0
	err := recoverControlResponse(outer, time.Now().Add(20*time.Millisecond), func(attempt context.Context) error {
		calls++
		<-attempt.Done()
		return errors.Join(attempt.Err(), &net.OpError{Op: "read", Net: "tcp", Err: independent})
	})
	if outer.Err() != nil || calls != 1 || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, independent) {
		t.Fatal("derived preparation deadline lost its independent final-attempt failure", err)
	}
}

func TestControlResponseRecoveryPreCanceledDoesNotInvokeMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	calls := 0
	err := recoverControlResponse(ctx, time.Time{}, func(context.Context) error {
		calls++
		return io.ErrUnexpectedEOF
	})
	if err != context.Canceled || calls != 0 {
		t.Fatal("pre-canceled recovery invoked or invented a mutation failure", err, calls)
	}
}
