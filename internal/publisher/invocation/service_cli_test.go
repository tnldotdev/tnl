package invocation

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	tunneltransport "github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceCLIKeepsOneCallerOwnedJournalAcrossAvailabilityChanges(t *testing.T) {
	for _, selected := range []struct {
		name     string
		protocol controlv1.ServiceProtocol
		public   bool
		address  string
	}{
		{"public HTTP", controlv1.ServiceProtocolHTTP, true, "https://app.example"},
		{"connector HTTP", controlv1.ServiceProtocolHTTP, false, ""},
		{"public postgres", controlv1.Postgres, true, ""},
	} {
		t.Run(selected.name, func(t *testing.T) {
			db, tunnel, saved, cfg := serviceCLIJournal(t, selected.protocol, selected.public)
			var events []string
			var numbers []uint64
			output := &Presentation{
				Provisioning: func(address string, number uint64) error {
					if address != selected.address {
						t.Errorf("address = %q, want %q", address, selected.address)
					}
					events, numbers = append(events, "provisioning"), append(numbers, number)
					return nil
				},
				Ready: func(address string, number uint64) error {
					if address != selected.address {
						t.Errorf("address = %q, want %q", address, selected.address)
					}
					events, numbers = append(events, "ready"), append(numbers, number)
					return nil
				},
				Stopped: func() error { events = append(events, "stopped"); return nil },
			}
			err := RunServiceCLI(t.Context(), tunnel, saved, cfg, output, func(ctx context.Context, run publisherservice.RunConfig) error {
				if run.ServiceID != cfg.ServiceID || run.Target != cfg.Target || run.Metadata.Protocol != cfg.Metadata.Protocol {
					t.Fatal("CLI bridge replaced the prepared service")
				}
				prepare := controlv1.ServiceRunPreparation{ServiceId: saved.Id, ServiceRunId: "srun_1111111111111111111111", RunNumber: 7}
				if err := run.Prepared(prepare); err != nil {
					return err
				}
				run.ObserveReadiness(publisherservice.RunStatus{Ready: true})
				if len(events) != 1 {
					t.Fatal("status announced readiness before the run owner", events)
				}
				if err := run.Ready(); err != nil {
					return err
				}
				for _, ready := range []bool{false, false, true, true} {
					run.ObserveReadiness(publisherservice.RunStatus{Ready: ready})
				}
				if err := run.Prepared(prepare); !errors.Is(err, publisheridentity.ErrScope) {
					t.Fatal("old preparation reset the current availability", err)
				}
				snapshot, err := db.Snapshot(ctx)
				if err != nil {
					return err
				}
				if len(snapshot.Tunnels) != 1 || snapshot.Tunnels[0].ID != tunnel.ID() ||
					snapshot.Tunnels[0].ServiceID != saved.Id || snapshot.Tunnels[0].PublishRunNumber != 7 ||
					snapshot.Tunnels[0].State != clientstate.TunnelStateReady {
					t.Fatal("availability replaced the journal or service run", snapshot)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(events, []string{"provisioning", "ready", "provisioning", "ready", "stopped"}) ||
				!reflect.DeepEqual(numbers, []uint64{7, 7, 7, 7}) {
				t.Fatal("unexpected availability transitions", events, numbers)
			}
			if tunnel.Context().Err() != nil {
				t.Fatal("CLI bridge finalized its caller's journal")
			}
		})
	}
}

func TestServiceCLIPreservesDeadlineAndIndependentReportingFailures(t *testing.T) {
	for _, failReport := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "reporting"}[failReport], func(t *testing.T) {
			_, tunnel, saved, cfg := serviceCLIJournal(t, controlv1.ServiceProtocolHTTP, true)
			reportErr := errors.New("reporting failed")
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			stopped := false
			output := &Presentation{Stopped: func() error { stopped = true; return nil }}
			if failReport {
				reports := 0
				output.Provisioning = func(string, uint64) error {
					reports++
					if reports > 1 {
						return reportErr
					}
					return nil
				}
			}
			err := RunServiceCLI(ctx, tunnel, saved, cfg, output, func(ctx context.Context, run publisherservice.RunConfig) error {
				preparation := controlv1.ServiceRunPreparation{ServiceId: saved.Id, RunNumber: 1}
				if err := run.Prepared(preparation); err != nil {
					return err
				}
				if err := run.Ready(); err != nil {
					return err
				}
				if failReport {
					run.ObserveReadiness(publisherservice.RunStatus{})
					return ctx.Err()
				}
				cancel(context.DeadlineExceeded)
				// a run returning nil after cancellation must not erase its deadline.
				return nil
			})
			want := error(context.DeadlineExceeded)
			if failReport {
				want = reportErr
			}
			if !errors.Is(err, want) || stopped {
				t.Fatal("CLI bridge reported success after a failure", err, stopped)
			}
		})
	}
}

func TestServiceCLIDiagnosticsUseActualTransportHealthTransitionsAndDrain(t *testing.T) {
	db, journal, saved, cfg := serviceCLIJournal(t, controlv1.ServiceProtocolHTTP, true)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var fallback []uint64
	targetWarnings, drains := 0, 0
	output := &Presentation{
		TransportFallback: func(number uint64, transport string) error {
			if transport != string(tunneltransport.TransportTLSTCP) {
				t.Error("fallback did not describe an established TLS/TCP session")
			}
			fallback = append(fallback, number)
			return nil
		},
		TargetUnavailable: func() error { targetWarnings++; return nil },
		Draining: func() error {
			drains++
			snapshot, err := db.Snapshot(t.Context())
			if err != nil || len(snapshot.Tunnels) != 1 || snapshot.Tunnels[0].State != clientstate.TunnelStateDraining {
				t.Fatal("real drain did not update the borrowed journal after cancellation", snapshot, err)
			}
			return nil
		},
	}
	err := RunServiceCLI(ctx, journal, saved, cfg, output, func(ctx context.Context, run publisherservice.RunConfig) error {
		if err := run.Prepared(controlv1.ServiceRunPreparation{ServiceId: saved.Id, RunNumber: 7}); err != nil {
			return err
		}
		current := publisherservice.RunStatus{TargetHealthy: true, LastCheck: time.Now(),
			Transports: [2]tunneltransport.Transport{tunneltransport.TransportQUIC, tunneltransport.TransportTLSTCP}}
		run.ObserveReadiness(current)
		if len(fallback) != 0 {
			t.Fatal("a transport without a connected session was reported as fallback")
		}
		current.Connected = [2]bool{true, true}
		current.Transports[1] = tunneltransport.TransportQUIC
		run.ObserveReadiness(current)
		if len(fallback) != 0 {
			t.Fatal("healthy QUIC sessions were reported as fallback")
		}
		current.Transports[1] = tunneltransport.TransportTLSTCP
		run.ObserveReadiness(current)
		run.ObserveReadiness(current)
		for _, healthy := range []bool{false, false, true, true, false, false, true} {
			current.TargetHealthy = healthy
			run.ObserveReadiness(current)
		}
		if targetWarnings != 2 {
			t.Fatal("target warnings did not follow health transitions", targetWarnings)
		}
		if err := run.Ready(); err != nil {
			return err
		}
		if err := run.Prepared(controlv1.ServiceRunPreparation{ServiceId: saved.Id, RunNumber: 8}); err != nil {
			return err
		}
		run.ObserveReadiness(current)
		if err := run.Ready(); err != nil {
			return err
		}
		cancel()
		current.Draining, current.Ready = true, false
		run.ObserveReadiness(current)
		run.ObserveReadiness(current)
		// a final availability observation must not revive the draining journal.
		current.Draining, current.Ready = false, true
		run.ObserveReadiness(current)
		return ctx.Err()
	})
	if err != nil || !reflect.DeepEqual(fallback, []uint64{7, 8}) || drains != 1 || journal.Context().Err() != nil {
		t.Fatal("semantic diagnostics changed the run or repeated signals", err, fallback, drains)
	}
}

func TestServiceCLIReportingFailuresCancelAndSurviveIndependentCleanup(t *testing.T) {
	for _, signal := range []string{"prepared hook", "ready hook", "provisioning", "ready", "transport", "target", "draining"} {
		t.Run(signal, func(t *testing.T) {
			_, journal, saved, cfg := serviceCLIJournal(t, controlv1.ServiceProtocolHTTP, true)
			report, cleanup := errors.New("signal reporting failed"), errors.New("independent run cleanup failed")
			stopped := false
			output := &Presentation{Stopped: func() error { stopped = true; return nil }}
			fail := func() error { return report }
			switch signal {
			case "prepared hook":
				cfg.Prepared = func(controlv1.ServiceRunPreparation) error { return fail() }
			case "ready hook":
				cfg.Ready = fail
			case "provisioning":
				output.Provisioning = func(string, uint64) error { return fail() }
			case "ready":
				output.Ready = func(string, uint64) error { return fail() }
			case "transport":
				output.TransportFallback = func(uint64, string) error { return fail() }
			case "target":
				output.TargetUnavailable = fail
			case "draining":
				output.Draining = fail
			}
			err := RunServiceCLI(t.Context(), journal, saved, cfg, output, func(ctx context.Context, run publisherservice.RunConfig) error {
				// even a run that returns only its cleanup result cannot discard
				// the reporting callback's independent error.
				_ = run.Prepared(controlv1.ServiceRunPreparation{ServiceId: saved.Id, RunNumber: 1})
				current := publisherservice.RunStatus{LastCheck: time.Now(), TargetHealthy: true}
				switch signal {
				case "ready", "ready hook":
					_ = run.Ready()
				case "transport":
					current.Connected[0], current.Transports[0] = true, tunneltransport.TransportTLSTCP
					run.ObserveReadiness(current)
				case "target":
					current.TargetHealthy = false
					run.ObserveReadiness(current)
				case "draining":
					current.Draining = true
					run.ObserveReadiness(current)
				}
				if ctx.Err() == nil {
					t.Error("reporting failure did not cancel the run")
				}
				return cleanup
			})
			if !errors.Is(err, report) || !errors.Is(err, cleanup) || stopped || journal.Context().Err() != nil {
				t.Fatal("reporting failure hid cleanup, reported success, or finalized the borrowed journal", err, stopped)
			}
		})
	}
}

func TestServiceCLIProvisioningStallTimerStopsAndResetsWithItsOwner(t *testing.T) {
	for _, mode := range []string{"warning", "ready", "replacement", "cancel", "return"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, journal, saved, cfg := serviceCLIJournal(t, controlv1.ServiceProtocolHTTP, true)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				stalled := make(chan uint64, 2)
				output := &Presentation{ProvisioningStalled: func(number uint64) error {
					stalled <- number
					return nil
				}}
				err := RunServiceCLI(ctx, journal, saved, cfg, output, func(ctx context.Context, run publisherservice.RunConfig) error {
					if err := run.Prepared(controlv1.ServiceRunPreparation{ServiceId: saved.Id, RunNumber: 1}); err != nil {
						return err
					}
					switch mode {
					case "ready":
						if err := run.Ready(); err != nil {
							return err
						}
					case "replacement":
						time.Sleep(time.Minute)
						if err := run.Prepared(controlv1.ServiceRunPreparation{ServiceId: saved.Id, RunNumber: 2}); err != nil {
							return err
						}
						time.Sleep(time.Minute)
						synctest.Wait()
						select {
						case number := <-stalled:
							t.Fatal("replaced preparation retained its old stall timer", number)
						default:
						}
					case "cancel":
						cancel()
					case "return":
						return nil
					}
					time.Sleep(2 * time.Minute)
					synctest.Wait()
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				time.Sleep(2 * time.Minute)
				synctest.Wait()
				var want []uint64
				if mode == "warning" {
					want = []uint64{1}
				} else if mode == "replacement" {
					want = []uint64{2}
				}
				var got []uint64
				for len(stalled) > 0 {
					got = append(got, <-stalled)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatal("stall warning repeated or outlived ready, replacement, cancellation, or return", got, want)
				}
			})
		})
	}
}

func TestServiceCLIJoinsEnteredStallCallbackAndRetainsItsError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, journal, saved, cfg := serviceCLIJournal(t, controlv1.ServiceProtocolHTTP, true)
		prepared, entered, returnRun, release := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		report, cleanup := errors.New("stall output failed"), errors.New("run cleanup failed")
		output := &Presentation{ProvisioningStalled: func(uint64) error {
			close(entered)
			<-release
			return errors.Join(context.Canceled, report)
		}}
		finished := make(chan error, 1)
		go func() {
			finished <- RunServiceCLI(t.Context(), journal, saved, cfg, output, func(ctx context.Context, run publisherservice.RunConfig) error {
				if err := run.Prepared(controlv1.ServiceRunPreparation{ServiceId: saved.Id, RunNumber: 1}); err != nil {
					return err
				}
				close(prepared)
				<-returnRun
				return cleanup
			})
		}()
		<-prepared
		time.Sleep(2 * time.Minute)
		<-entered
		close(returnRun)
		synctest.Wait()
		select {
		case err := <-finished:
			t.Fatal("CLI observation returned without joining entered stall output", err)
		default:
		}
		unblock()
		if err := <-finished; !errors.Is(err, report) || !errors.Is(err, cleanup) {
			t.Fatal("joined stall output lost an independent reporting or cleanup failure", err)
		}
	})
}

func serviceCLIJournal(t *testing.T, protocol controlv1.ServiceProtocol, public bool) (*clientstate.Database, *clientstate.Tunnel, controlv1.Service, publisherservice.RunConfig) {
	t.Helper()
	db, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	target := "http://127.0.0.1:3000"
	if protocol != controlv1.ServiceProtocolHTTP {
		target = "127.0.0.1:5432"
	}
	saved := controlv1.Service{Id: "svc_1111111111111111111111", Protocol: protocol,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "app.example", Public: public, Port: 443}}
	tunnel, err := db.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish,
		Server: "https://control.example", Project: t.TempDir(), Target: target, ServiceID: saved.Id, ServiceProtocol: protocol})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Finish(context.WithoutCancel(t.Context()), nil) })
	return db, tunnel, saved, publisherservice.RunConfig{ServiceID: saved.Id, Target: target, Metadata: publisheridentity.ServiceMetadata(saved)}
}
