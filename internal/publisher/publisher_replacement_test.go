package publisher

import (
	"context"
	"errors"
	"slices"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestRunPreservesExpiredRunWhenReplacementCanceled(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(map[bool]string{false: "request", true: "retry"}[retry], func(t *testing.T) {
			control, _, _ := newCertificateTransactionTest(t)
			config := startCertificateTLSYamuxHarness(t, control)
			control.heartbeat = func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
				return controlv1.PublishRunHeartbeat{}, clientcontrol.ErrStatusConflict
			}
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			stop := errors.New("test stopped replacement")
			attempts := 0
			config.Control = replacementTestControl{certificateTestControl: control, createRun: func(ctx context.Context, id, key string) (controlv1.PublishRunSetup, error) {
				attempts++
				if attempts == 1 {
					return control.CreatePublishRun(ctx, id, key, controlv1.HTTPProtection{})
				}
				cancel(stop)
				if retry {
					return controlv1.PublishRunSetup{}, clientcontrol.ErrUnavailable
				}
				return controlv1.PublishRunSetup{}, ctx.Err()
			}}
			err := Run(ctx, config)
			if !errors.Is(err, clientcontrol.ErrStatusConflict) || !errors.Is(err, stop) || attempts != 2 {
				t.Fatalf("replacement cancellation lost the expired run or cancellation cause: attempts=%d error=%v", attempts, err)
			}
			if !slices.Equal(control.closedSessions, []string{control.setup.PublishRun.Id}) {
				t.Fatalf("closed publish runs = %v", control.closedSessions)
			}
		})
	}
}

func TestRunDoesNotRetainExpiredRunAfterReplacementStarts(t *testing.T) {
	control, _, _ := newCertificateTransactionTest(t)
	config := startCertificateTLSYamuxHarness(t, control)
	stop := errors.New("replacement heartbeat failed")
	heartbeats := 0
	control.heartbeat = func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
		heartbeats++
		if heartbeats == 1 {
			return controlv1.PublishRunHeartbeat{}, clientcontrol.ErrStatusConflict
		}
		return controlv1.PublishRunHeartbeat{}, stop
	}
	err := Run(t.Context(), config)
	if !errors.Is(err, stop) || errors.Is(err, clientcontrol.ErrStatusConflict) || heartbeats != 2 || len(control.closedSessions) != 2 {
		t.Fatalf("replacement retained the previous failure: heartbeats=%d closed=%v error=%v", heartbeats, control.closedSessions, err)
	}
}

func TestRunDoesNotClassifyUnrelatedCreateFailureAsCancellation(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(map[int]string{1: "initial", 2: "replacement"}[failAt], func(t *testing.T) {
			control, _, _ := newCertificateTransactionTest(t)
			config := startCertificateTLSYamuxHarness(t, control)
			control.heartbeat = func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
				return controlv1.PublishRunHeartbeat{}, clientcontrol.ErrStatusConflict
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failure := errors.New("invalid publish run response")
			attempts := 0
			config.Control = replacementTestControl{certificateTestControl: control, createRun: func(ctx context.Context, id, key string) (controlv1.PublishRunSetup, error) {
				attempts++
				if attempts < failAt {
					return control.CreatePublishRun(ctx, id, key, controlv1.HTTPProtection{})
				}
				cancel()
				return controlv1.PublishRunSetup{}, failure
			}}
			err := Run(ctx, config)
			if err != failure || errors.Is(err, context.Canceled) || attempts != failAt || len(control.closedSessions) != failAt-1 {
				t.Fatalf("unrelated create failure changed after parent cancellation: attempts=%d closed=%v error=%v", attempts, control.closedSessions, err)
			}
		})
	}
}

type replacementTestControl struct {
	*certificateTestControl
	createRun func(context.Context, string, string) (controlv1.PublishRunSetup, error)
}

func (c replacementTestControl) CreatePublishRun(ctx context.Context, id, key string, _ controlv1.HTTPProtection, _ ...string) (controlv1.PublishRunSetup, error) {
	return c.createRun(ctx, id, key)
}
