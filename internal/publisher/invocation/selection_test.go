package invocation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type testClientIPLookup struct {
	response controlv1.ClientIPResponse
	err      error
	calls    int
}

func TestResolveVisitorAccessCountsNormalizedPrefixes(t *testing.T) {
	lookup := &testClientIPLookup{err: errors.New("unexpected IP lookup")}
	prefixes := make([]string, 257)
	for index := range prefixes {
		prefixes[index] = fmt.Sprintf("2001:db8::%x", index)
	}
	withAliases := append(slices.Clone(prefixes[:256]), prefixes[0], prefixes[0]+"/128")
	value, err := resolveVisitorAccess(t.Context(), lookup, nil, false, withAliases)
	if err != nil || len(value.prefixes) != 256 || value.access != controlv1.Restricted || lookup.calls != 0 {
		t.Fatal("CLI aliases consumed the limit or granted access", value, err)
	}
	if _, err := resolveVisitorAccess(t.Context(), lookup, nil, false, prefixes); !errors.Is(err, authorization.ErrIPPrefixLimit) {
		t.Fatal("CLI prefix limit lost its owned diagnostic", err)
	}
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

func TestSignedInPublishAccessDefaultsOnlyDemoToAnonymous(t *testing.T) {
	lookup := &testClientIPLookup{err: errors.New("unexpected IP lookup")}
	for _, tc := range []struct {
		name     string
		flags    PublicOptions
		mode     controlv1.VisitorAccessMode
		prefixes []string
		explicit bool
	}{
		{name: "ordinary", mode: controlv1.Restricted},
		{name: "demo", flags: PublicOptions{Demo: true}, mode: controlv1.Anonymous, explicit: true},
		{name: "demo with filter", flags: PublicOptions{Demo: true, IP: []string{"192.0.2.3/24"}},
			mode: controlv1.Anonymous, prefixes: []string{"192.0.2.0/24"}, explicit: true},
		{name: "restricted demo", flags: PublicOptions{Demo: true, Access: &config.Access{Mode: "restricted"}},
			mode: controlv1.Restricted, explicit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			access, err := resolveSignedInPublishAccess(t.Context(), lookup, tc.flags)
			if err != nil || access.access != tc.mode || access.explicit != tc.explicit || !slices.Equal(access.prefixes, tc.prefixes) || lookup.calls != 0 {
				t.Fatalf("unexpected publish access: %+v, %v", access, err)
			}
		})
	}
}

func TestResolveVisitorAccessUsesCurrentIPOnlyWhenExplicit(t *testing.T) {
	lookup := &testClientIPLookup{response: controlv1.ClientIPResponse{Ip: "192.0.2.4"}}
	policy, err := resolveVisitorAccess(t.Context(), lookup, nil, false, []string{"current", "::ffff:192.0.2.4", "198.51.100.8/24"})
	if err != nil || policy.access != controlv1.Restricted || !reflect.DeepEqual(policy.prefixes, []string{"192.0.2.4/32", "198.51.100.0/24"}) || lookup.calls != 1 {
		t.Fatalf("policy=%+v, calls=%d, error=%v", policy, lookup.calls, err)
	}
	lookup.err = errors.New("unavailable")
	if _, err := resolveVisitorAccess(t.Context(), lookup, nil, false, []string{"current"}); err == nil {
		t.Fatal("explicit current-IP lookup failure was accepted")
	}
}
