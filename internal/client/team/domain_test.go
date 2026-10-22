package team

import (
	"context"
	"errors"
	"testing"
	"time"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type claimTestAPI struct {
	claim      authorityv1.Domain
	reads      [][]authorityv1.Domain
	readErr    error
	onRead     func(context.Context) error
	claimCalls int
	readCalls  int
}

func (api *claimTestAPI) ClaimTeamDomain(_ context.Context, teamID, name, key string, makeDefault bool) (authorityv1.Domain, error) {
	api.claimCalls++
	if teamID != "team_1" || name != "claimed.example" || key != "key_1" || !makeDefault {
		return authorityv1.Domain{}, errors.New("unexpected claim request")
	}
	return api.claim, nil
}

func (api *claimTestAPI) ListTeamDomains(ctx context.Context, teamID string) (authorityv1.DomainPage, error) {
	api.readCalls++
	if teamID != "team_1" {
		return authorityv1.DomainPage{}, errors.New("unexpected team ID")
	}
	if api.onRead != nil {
		if err := api.onRead(ctx); err != nil {
			return authorityv1.DomainPage{}, err
		}
	}
	if api.readErr != nil {
		return authorityv1.DomainPage{}, api.readErr
	}
	if len(api.reads) == 0 {
		return authorityv1.DomainPage{}, errors.New("unexpected domain read")
	}
	index := min(api.readCalls-1, len(api.reads)-1)
	return authorityv1.DomainPage{Domains: api.reads[index]}, nil
}

func TestDomainClaimWaitsForRecordsOnly(t *testing.T) {
	records := []authorityv1.DNSRecord{{Name: "claimed.example", Type: "NS", Value: "ns-1.example"}}
	pending := authorityv1.Domain{CanonicalDomain: "claimed.example", Id: "domain_1", State: authorityv1.DomainStatePending}
	withRecords := pending
	withRecords.RequiredRecords = records
	failed := pending
	failed.State = authorityv1.DomainStateFailed
	for _, test := range []struct {
		name      string
		claim     authorityv1.Domain
		reads     [][]authorityv1.Domain
		polls     int
		wantReads int
		wantState authorityv1.DomainState
		wantNS    bool
	}{
		{name: "immediate", claim: withRecords, wantNS: true, wantState: authorityv1.DomainStatePending},
		{name: "delayed", claim: pending, reads: [][]authorityv1.Domain{{}, {pending}, {withRecords}}, polls: 3, wantReads: 3, wantNS: true, wantState: authorityv1.DomainStatePending},
		{name: "failed", claim: pending, reads: [][]authorityv1.Domain{{failed}}, polls: 1, wantReads: 1, wantState: authorityv1.DomainStateFailed},
		{name: "failed_response", claim: failed, wantState: authorityv1.DomainStateFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &claimTestAPI{claim: test.claim, reads: test.reads}
			polls := 0
			got, timedOut, err := ClaimAndWaitForDomainRecords(context.Background(), api, "team_1", "claimed.example", "key_1", true, DomainClaimWait{
				Timeout: time.Second,
				Poll: func(context.Context) error {
					polls++
					return nil
				},
			})
			if err != nil || timedOut || got.State != test.wantState || (len(got.RequiredRecords) > 0) != test.wantNS {
				t.Fatalf("claim result = %#v, timeout %t, error %v", got, timedOut, err)
			}
			if api.claimCalls != 1 || api.readCalls != test.wantReads || polls != test.polls {
				t.Fatalf("claims %d, reads %d, polls %d", api.claimCalls, api.readCalls, polls)
			}
		})
	}
}

func TestDomainClaimWaitTimeoutAndReadErrors(t *testing.T) {
	pending := authorityv1.Domain{CanonicalDomain: "claimed.example", Id: "domain_1", State: authorityv1.DomainStatePending}
	readFailure := errors.New("authority read unavailable")
	readsBeforeStall := 0
	for _, test := range []struct {
		name      string
		poll      func(context.Context) error
		onRead    func(context.Context) error
		reads     [][]authorityv1.Domain
		readErr   error
		wantError error
		timedOut  bool
		wantReads int
	}{
		{name: "stall", poll: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, timedOut: true},
		{name: "stall_after_read", poll: func(ctx context.Context) error {
			readsBeforeStall++
			if readsBeforeStall > 1 {
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		}, reads: [][]authorityv1.Domain{{pending}}, timedOut: true, wantReads: 1},
		{name: "read_error", poll: func(context.Context) error { return nil }, readErr: readFailure, wantError: readFailure, wantReads: 1},
		{name: "canceled", poll: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, wantError: context.Canceled},
		{name: "canceled_read", poll: func(context.Context) error { return nil }, onRead: func(ctx context.Context) error {
			return ctx.Err()
		}, wantError: context.Canceled, wantReads: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &claimTestAPI{claim: pending, reads: test.reads, readErr: test.readErr, onRead: test.onRead}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.name == "canceled" {
				apiPoll := test.poll
				test.poll = func(ctx context.Context) error { cancel(); return apiPoll(ctx) }
			}
			if test.name == "canceled_read" {
				read := api.onRead
				api.onRead = func(ctx context.Context) error { cancel(); return read(ctx) }
			}
			timeout := time.Second
			if test.timedOut {
				timeout = 5 * time.Millisecond
			}
			got, timedOut, err := ClaimAndWaitForDomainRecords(ctx, api, "team_1", "claimed.example", "key_1", true, DomainClaimWait{Timeout: timeout, Poll: test.poll})
			if test.wantError != nil && !errors.Is(err, test.wantError) || test.wantError == nil && err != nil || timedOut != test.timedOut || api.claimCalls != 1 || api.readCalls != test.wantReads {
				t.Fatalf("claim result = %#v, timeout %t, error %v; claims %d, reads %d", got, timedOut, err, api.claimCalls, api.readCalls)
			}
		})
	}
}
