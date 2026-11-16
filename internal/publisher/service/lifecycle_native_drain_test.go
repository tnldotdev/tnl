package service

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
)

type drainTargetResolver struct {
	entered chan struct{}
	release <-chan struct{}
	cause   error
	calls   atomic.Int32
}

func (r *drainTargetResolver) ResolveTarget(ctx context.Context) (string, *tls.Config, error) {
	r.calls.Add(1)
	close(r.entered)
	select {
	case <-r.release:
		return "", nil, r.cause
	case <-ctx.Done():
		return "", nil, errors.Join(context.Cause(ctx), r.cause)
	}
}

func TestServiceRunDrainRetainsEveryProtocolWorkerWithinOriginalBound(t *testing.T) {
	for _, protocol := range []config.ProtocolName{config.ProtocolTCP, config.ProtocolPostgres, config.ProtocolMySQL, config.ProtocolKubernetes} {
		for _, finish := range []string{"completed", "deadline", "revoked"} {
			t.Run(string(protocol)+"/"+finish, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					_, bound, ref, _ := privateFixture(t, "127.0.0.1:1")
					bound.prepared.managedProtocol = protocol
					released := make(chan struct{})
					release := sync.OnceFunc(func() { close(released) })
					defer release()
					cause := errors.New("independent entered target failure")
					resolver := &drainTargetResolver{entered: make(chan struct{}), release: released, cause: cause}
					bound.prepared.targetResolver = resolver
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					forwarded := make(chan error, 1)
					go func() {
						forwarded <- bound.forwardManaged(ctx, nil, servicestream.CertificateVisitor{}, "", nil)
					}()
					<-resolver.entered
					before := time.Now()
					until := before.Add(time.Second)
					if err := bound.startDrain(until); err != nil {
						t.Fatal(err)
					}
					joined := make(chan error, 1)
					go func() { joined <- bound.joinDrain() }()
					synctest.Wait()
					select {
					case err := <-joined:
						t.Fatal("drain retired a native worker before its owner joined", err)
					default:
					}
					if _, available := bound.reserveStream(ref); available {
						t.Fatal("draining run admitted new public work")
					}
					if err := bound.forwardManaged(ctx, nil, servicestream.CertificateVisitor{}, "", nil); !errors.Is(err, ErrPrivateStream) {
						t.Fatal("draining run entered new target work", err)
					}
					if err := bound.startDrain(until.Add(time.Hour)); err != nil || !bound.drainUntil.Equal(until) {
						t.Fatal("another drain request extended the original bound", err)
					}
					switch finish {
					case "completed":
						release()
					case "deadline":
						time.Sleep(time.Second)
					case "revoked":
						cancel()
					}
					err := <-forwarded
					if !errors.Is(err, cause) || finish == "deadline" && !errors.Is(err, context.Canceled) || finish == "revoked" && !errors.Is(err, context.Canceled) {
						t.Fatal("drain lost its independent operation or stop cause", err)
					}
					drained := <-joined
					if finish == "deadline" {
						if !errors.Is(drained, context.DeadlineExceeded) || !time.Now().Equal(until) {
							t.Fatal("native worker did not join at the exact original drain deadline", drained, time.Since(before))
						}
					} else if drained != nil || !time.Now().Equal(before) {
						t.Fatal("completion or revocation waited for graceful drain expiry", drained, time.Since(before))
					}
					cancel()
					time.Sleep(2 * time.Second)
					synctest.Wait()
					if resolver.calls.Load() != 1 {
						t.Fatal("drain restarted target work after return", resolver.calls.Load())
					}
				})
			})
		}
	}
}
