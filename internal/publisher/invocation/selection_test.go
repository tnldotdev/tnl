package invocation

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type testClientIPLookup struct {
	response controlv1.ClientIPResponse
	err      error
	calls    int
}

func (l *testClientIPLookup) ClientIP(context.Context) (controlv1.ClientIPResponse, error) {
	l.calls++
	return l.response, l.err
}

func TestResolveVisitorAccessNeverAddsAnImplicitIP(t *testing.T) {
	lookup := &testClientIPLookup{err: errors.New("unexpected IP lookup")}
	for _, tc := range []struct {
		configured *config.Access
		anonymous  bool
		mode       controlv1.VisitorAccessMode
		prefixes   []string
		explicit   bool
	}{
		{mode: controlv1.Restricted},
		{anonymous: true, mode: controlv1.Anonymous, explicit: true},
		{configured: &config.Access{IP: []string{"192.0.2.0/24"}}, mode: controlv1.Restricted, prefixes: []string{"192.0.2.0/24"}, explicit: true},
	} {
		policy, err := resolveVisitorAccess(t.Context(), lookup, tc.configured, tc.anonymous, nil)
		if err != nil || policy.access != tc.mode || policy.explicit != tc.explicit || !slices.Equal(policy.prefixes, tc.prefixes) {
			t.Fatalf("policy=%+v, want=%+v, error=%v", policy, tc, err)
		}
	}
	if lookup.calls != 0 {
		t.Fatalf("implicit current-IP lookup: %d calls", lookup.calls)
	}
}

func TestResolveVisitorAccessUsesCurrentIPOnlyWhenExplicit(t *testing.T) {
	lookup := &testClientIPLookup{response: controlv1.ClientIPResponse{Ip: "192.0.2.4"}}
	policy, err := resolveVisitorAccess(t.Context(), lookup, nil, false, []string{"current", "198.51.100.8/24"})
	if err != nil || policy.access != controlv1.Restricted || !reflect.DeepEqual(policy.prefixes, []string{"192.0.2.4/32", "198.51.100.0/24"}) || lookup.calls != 1 {
		t.Fatalf("policy=%+v, calls=%d, error=%v", policy, lookup.calls, err)
	}
	lookup.err = errors.New("unavailable")
	if _, err := resolveVisitorAccess(t.Context(), lookup, nil, false, []string{"current"}); err == nil {
		t.Fatal("explicit current-IP lookup failure was accepted")
	}
}

func TestPublisherConfigPreservesEphemeralRouteChoice(t *testing.T) {
	configured := (publisherServices{ephemeral: true}).config("http://127.0.0.1:3000", nil, publisher.ApplicationLimits{Concurrency: 750})
	if !configured.Ephemeral {
		t.Fatal("ephemeral route choice was not passed to the publisher")
	}
	if configured.Limits.Concurrency != 750 {
		t.Fatalf("concurrency = %d", configured.Limits.Concurrency)
	}
}
