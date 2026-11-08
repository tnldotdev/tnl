package discovery

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type canceledCaller struct {
	finish func()
	cause  error
}

func (c canceledCaller) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	c.finish()
	return &sts.GetCallerIdentityOutput{}, c.cause
}

func TestAWSDiscoveryPreservesCancellationAfterSDKResponse(t *testing.T) {
	for _, expired := range []bool{false, true} {
		for _, returned := range []error{nil, errors.New("fixture provider failure")} {
			t.Run(map[bool]string{true: "deadline", false: "cancel"}[expired]+"/"+map[bool]string{true: "empty response", false: "provider failure"}[returned == nil], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()
					finish := func() { cancel() }
					want := context.Canceled
					if expired {
						finish = func() { <-ctx.Done() }
						want = context.DeadlineExceeded
					}
					provider := AWS{Load: func(context.Context, string) (Clients, error) {
						return Clients{Caller: canceledCaller{finish: finish, cause: returned}}, nil
					}}
					target, err := provider.Discover(ctx, Request{Type: "eks", Region: "us-east-1", Cluster: "demo", Protocol: "kubernetes"})
					if !errors.Is(err, want) || target.Address != "" {
						t.Fatalf("SDK completion lost cancellation: target=%s error=%v", target, err)
					}
					if returned != nil && !errors.Is(err, returned) {
						t.Fatal("cancellation discarded the SDK failure")
					}
				})
			})
		}
	}
}

var _ Caller = canceledCaller{}
