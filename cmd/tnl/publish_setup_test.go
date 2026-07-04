package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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

func TestResolveIPPolicyDefaultsToCurrentIPAndAddsExplicitPrefixes(t *testing.T) {
	lookup := &testClientIPLookup{response: controlv1.ClientIPResponse{Ip: "192.0.2.4"}}
	policy, current, err := resolveIPPolicy(t.Context(), lookup, []string{"198.51.100.8/24"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.4/32", "198.51.100.0/24"}
	if current != "192.0.2.4" || !reflect.DeepEqual(policy, want) || lookup.calls != 1 {
		t.Fatalf("policy = %#v, current = %q, calls = %d", policy, current, lookup.calls)
	}
}

func TestResolveIPPolicyPublicDoesNotLookUpCurrentIP(t *testing.T) {
	lookup := &testClientIPLookup{err: errors.New("must not be called")}
	policy, current, err := resolveIPPolicy(t.Context(), lookup, nil, true)
	if err != nil || policy == nil || len(policy) != 0 || current != "" || lookup.calls != 0 {
		t.Fatalf("policy = %#v, current = %q, calls = %d, error = %v", policy, current, lookup.calls, err)
	}
}

func TestResolveIPPolicyFailsWhenCurrentIPCannotBeResolved(t *testing.T) {
	lookup := &testClientIPLookup{err: errors.New("unavailable")}
	if _, _, err := resolveIPPolicy(t.Context(), lookup, nil, false); err == nil {
		t.Fatal("current-IP lookup failure was accepted")
	}
}

func TestPublisherConfigPreservesEphemeralRouteChoice(t *testing.T) {
	configured := (publisherServices{ephemeral: true}).config("http://127.0.0.1:3000", nil)
	if !configured.Ephemeral {
		t.Fatal("ephemeral route choice was not passed to the publisher")
	}
}
