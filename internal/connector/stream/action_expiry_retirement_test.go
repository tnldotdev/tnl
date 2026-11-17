package stream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/connectorfixture"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type actionExpiryControl struct {
	Control
	retire func(context.Context, string, string, controlv1.ConnectorPeerPairRetireRequest) (controlv1.ConnectorPeerPairRetirement, error)
	close  func(context.Context) error
}

func (c actionExpiryControl) RetireConnectorPeerPair(ctx context.Context, service, pair string, body controlv1.ConnectorPeerPairRetireRequest) (controlv1.ConnectorPeerPairRetirement, error) {
	return c.retire(ctx, service, pair, body)
}

func (c actionExpiryControl) Close(ctx context.Context) error { return c.close(ctx) }

type actionExpirySession struct {
	muxsession.Session
	closes int
	err    error
}

func (s *actionExpirySession) Close() error { s.closes++; return s.err }

type actionExpiryConn struct {
	net.Conn
	reads, writes int
}

func (c *actionExpiryConn) Read([]byte) (int, error)  { c.reads++; return 0, nil }
func (c *actionExpiryConn) Write([]byte) (int, error) { c.writes++; return 0, nil }

func actionExpiryRetirement(t *testing.T, p *connectorConnection) *connectorfixture.Retirement {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{29}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	p.signer = Signer{PublicKey: public, Sign: func(message []byte) []byte { return ed25519.Sign(private, message) }}
	key := [32]byte{9, 3}
	pair := controlv1.ConnectorPeerPair{
		ServiceId: "svc_aaaaaaaaaaaaaaaaaaaaaa", ServiceRunId: "srun_aaaaaaaaaaaaaaaaaaaaaa", RunNumber: 1,
		PublisherIdentityId: "pub_aaaaaaaaaaaaaaaaaaaaaa", PairId: "cpp_aaaaaaaaaaaaaaaaaaaaaa",
		DeliveryId: "AQEBAQEBAQEBAQEBAQEBAQ", ObservedAt: time.Now().Add(-time.Minute), ExpiresAt: p.until,
		SessionKey: base64.RawURLEncoding.EncodeToString(key[:]),
	}
	p.pair = pair
	if err := p.captureRetirement(pair); err != nil {
		t.Fatal(err)
	}
	return connectorfixture.NewRetirement(pair, p.owner, public, key)
}

func TestActionExpiryRetirementUsesRemainingOriginalStopBudget(t *testing.T) {
	for _, earlierParent := range []bool{false, true} {
		for _, independent := range []bool{false, true} {
			name := "owner budget"
			if earlierParent {
				name = "earlier actual parent"
			}
			if independent {
				name += "/independent failures"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					started := time.Now()
					stopBudget, stop := context.WithDeadline(t.Context(), started.Add(10*time.Second))
					defer stop()
					parent := t.Context()
					if earlierParent {
						var cancel context.CancelFunc
						parent, cancel = context.WithDeadline(parent, started.Add(4*time.Second))
						defer cancel()
					}
					serving, cancelServing := context.WithCancelCause(parent)
					packets, cancelPackets := context.WithCancelCause(context.WithoutCancel(parent))
					defer cancelPackets(context.Canceled)
					cleanup := newConnectorCleanup(parent, func() context.Context { return stopBudget })
					defer cleanup.close()
					authorityUntil := started.Add(time.Second)
					cleanup.observe(authorityUntil)
					session := &actionExpirySession{}
					p := &connectorConnection{
						ctx: serving, packetCtx: packets, packetCancel: cancelPackets, cleanup: cleanup,
						owner: "ik_aaaaaaaaaaaaaaaaaaaaaa", session: session, until: authorityUntil,
						run: Run{ValidUntil: authorityUntil}, permission: controlv1.VisitorTokenResponse{ExpiresAt: authorityUntil},
						preparedUntil: authorityUntil,
					}
					p.cancel = func(cause error) { cleanup.begin(); cancelServing(cause) }
					authority := actionExpiryRetirement(t, p)
					retireFailure := errors.New("independent signed retirement failure")
					controlFailure := errors.New("independent control close failure")
					physicalFailure := errors.New("independent physical close failure")
					retirements, controlCloses := 0, 0
					var retirementDeadline time.Time
					p.config.Control = actionExpiryControl{
						retire: func(ctx context.Context, service, pair string, body controlv1.ConnectorPeerPairRetireRequest) (controlv1.ConnectorPeerPairRetirement, error) {
							retirements++
							retirementDeadline, _ = ctx.Deadline()
							if context.Cause(ctx) != nil || !retirementDeadline.After(time.Now()) ||
								retirementDeadline.After(started.Add(5*time.Second)) ||
								earlierParent && retirementDeadline.After(started.Add(4*time.Second)) {
								t.Error("retirement lost the original remaining stop/actual parent bound", retirementDeadline, context.Cause(ctx))
							}
							receipt, err := authority.Retire(ctx, service, pair, body)
							if err != nil {
								t.Error("negative retirement lost its captured signature or exact scope", err)
							}
							if independent {
								return receipt, errors.Join(context.DeadlineExceeded, retireFailure)
							}
							return receipt, err
						},
						close: func(ctx context.Context) error {
							controlCloses++
							if got, _ := ctx.Deadline(); !got.Equal(retirementDeadline) {
								t.Error("control close restarted the original cleanup budget", got, retirementDeadline)
							}
							if independent {
								return errors.Join(ErrServiceConnection, controlFailure)
							}
							return context.Cause(ctx)
						},
					}
					if independent {
						session.err = &muxsession.QUICTransportCloseError{Err: errors.Join(context.Canceled, physicalFailure)}
					}
					// stop starts once, before authority expires; time spent joining is
					// not returned as a fresh five- or ten-second cleanup phase.
					cleanup.begin()
					time.Sleep(2 * time.Second)
					synctest.Wait()
					local := &actionExpiryConn{}
					if err := p.Forward(t.Context(), local); err != ErrServiceConnection {
						t.Fatal("expired owner admitted an application", err)
					}
					prepared := &PreparedConnector{ctx: parent, conn: local, stream: streamPrepared{}, permission: permissionUsable{}, permissionUntil: authorityUntil}
					use := &preparedConnectorUse{owner: prepared, ctx: parent}
					if n, err := use.Read(make([]byte, 1)); n != 0 || err != ErrServiceConnection {
						t.Fatal("expired preparation returned application bytes", n, err)
					}
					if n, err := use.Write([]byte("not authorized")); n != 0 || err != ErrServiceConnection {
						t.Fatal("expired preparation sent application bytes", n, err)
					}
					if local.reads != 0 || local.writes != 0 || p.admitDirectPacket(tunnelv1.PeerPacket{BindingGeneration: 1, Kind: tunnelv1.PeerData}) {
						t.Fatal("negative cleanup borrowed serving authority")
					}
					useRelease, workerRelease := make(chan struct{}), make(chan struct{})
					p.uses.Go(func() { <-useRelease })
					p.workers.Go(func() { <-workerRelease })
					done := make(chan error, 1)
					var closers sync.WaitGroup
					closers.Go(func() {
						err := p.Close(cleanup.context())
						done <- errors.Join(err, p.config.Control.Close(cleanup.context()))
					})
					synctest.Wait()
					if retirements != 0 || session.closes != 0 {
						t.Fatal("retirement/physical cleanup preceded the entered use join")
					}
					close(useRelease)
					synctest.Wait()
					select {
					case err := <-done:
						t.Fatal("cleanup returned without joining its owned worker", err)
					default:
					}
					close(workerRelease)
					err := <-done
					closers.Wait()
					if retirements != 1 || controlCloses != 1 || session.closes != 1 {
						t.Errorf("expired serving authority skipped or repeated required cleanup: retire=%d control=%d physical=%d", retirements, controlCloses, session.closes)
					}
					if independent {
						for _, cause := range []error{retireFailure, controlFailure, physicalFailure, context.DeadlineExceeded, ErrServiceConnection} {
							if !errors.Is(err, cause) {
								t.Error("expiry hid an independent cleanup failure", cause, err)
							}
						}
					} else if err != nil {
						t.Error("serving expiry consumed the unspent negative cleanup budget", err)
					}
					_ = p.Close(stopBudget)
					if session.closes != 1 || retirements != 1 || !p.until.Equal(authorityUntil) {
						t.Error("repeated close restarted retirement or extended serving authority")
					}
				})
			})
		}
	}
}

func TestActionExpiryRetirementDoesNotRestartSpentStopBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		original, stop := context.WithTimeout(t.Context(), 10*time.Second)
		defer stop()
		cleanup := newConnectorCleanup(t.Context(), func() context.Context { return original })
		defer cleanup.close()
		cleanup.begin()
		first := cleanup.context()
		deadline, _ := first.Deadline()
		time.Sleep(11 * time.Second)
		synctest.Wait()
		if cleanup.context() != first || context.Cause(first) != context.DeadlineExceeded {
			t.Fatal("spent shutdown was replaced with a fresh budget")
		}
		if got, _ := cleanup.context().Deadline(); !got.Equal(deadline) {
			t.Fatal("spent shutdown changed its deadline", got, deadline)
		}
		p := &connectorConnection{until: time.Now().Add(-time.Second), owner: "ik_aaaaaaaaaaaaaaaaaaaaaa"}
		actionExpiryRetirement(t, p)
		calls := 0
		control := actionExpiryControl{retire: func(context.Context, string, string, controlv1.ConnectorPeerPairRetireRequest) (controlv1.ConnectorPeerPairRetirement, error) {
			calls++
			return controlv1.ConnectorPeerPairRetirement{}, nil
		}}
		if err := p.retirement.retire(first, control, p.owner); !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
			t.Fatal("spent shutdown attempted another signed mutation", err, calls)
		}
	})
}
