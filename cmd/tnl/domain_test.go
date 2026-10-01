package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestDomainClaimPresentation(t *testing.T) {
	records := []authorityv1.DNSRecord{{Name: "claimed.example", Type: "NS", Value: "ns-1.example"}}
	for _, test := range []struct {
		name        string
		domain      authorityv1.Domain
		makeDefault bool
		state       string
		footer      string
	}{
		{
			name: "provisioning", domain: authorityv1.Domain{State: authorityv1.DomainStatePending},
			state: "provisioning", footer: "run tnl domain status to check DNS setup",
		},
		{
			name: "provisioning_default", domain: authorityv1.Domain{State: authorityv1.DomainStatePending}, makeDefault: true,
			state: "provisioning", footer: "will become default; run tnl domain status",
		},
		{
			name: "verification", domain: authorityv1.Domain{State: authorityv1.DomainStatePending, RequiredRecords: records},
			state: "verification required", footer: "add the DNS records to continue",
		},
		{
			name: "verification_default", domain: authorityv1.Domain{State: authorityv1.DomainStatePending, RequiredRecords: records}, makeDefault: true,
			state: "verification required", footer: "add the DNS records; this domain will become the default",
		},
		{
			name: "ready_default", domain: authorityv1.Domain{State: authorityv1.DomainStateReady}, makeDefault: true,
			state: "ready", footer: "selected as the default domain",
		},
		{
			name: "failed", domain: authorityv1.Domain{State: authorityv1.DomainStateFailed}, makeDefault: true,
			state: "failed", footer: "ask your team admin to check DNS setup",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, footer := domainClaimPresentation(test.domain, test.makeDefault)
			if state != test.state || footer != test.footer {
				t.Fatalf("presentation = %q, %q; want %q, %q", state, footer, test.state, test.footer)
			}
		})
	}
}

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
			got, timedOut, err := claimAndWaitForDomainRecords(context.Background(), api, "team_1", "claimed.example", "key_1", true, domainClaimWait{
				timeout: time.Second,
				poll: func(context.Context) error {
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
			var output bytes.Buffer
			if err := writeDomainClaim(&output, got, true, timedOut); err != nil {
				t.Fatal(err)
			}
			if test.wantNS && !strings.Contains(output.String(), "ns-1.example") || test.wantState == authorityv1.DomainStateFailed && !strings.Contains(output.String(), "-- failed ") {
				t.Fatalf("claim output: %s", output.String())
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
			got, timedOut, err := claimAndWaitForDomainRecords(ctx, api, "team_1", "claimed.example", "key_1", true, domainClaimWait{timeout: timeout, poll: test.poll})
			if test.wantError != nil && !errors.Is(err, test.wantError) || test.wantError == nil && err != nil || timedOut != test.timedOut || api.claimCalls != 1 || api.readCalls != test.wantReads {
				t.Fatalf("claim result = %#v, timeout %t, error %v; claims %d, reads %d", got, timedOut, err, api.claimCalls, api.readCalls)
			}
			if timedOut {
				var output bytes.Buffer
				if err := writeDomainClaim(&output, got, true, timedOut); err != nil {
					t.Fatal(err)
				}
				for _, want := range []string{"claim saved", "DNS records not yet available", "tnl domain status claimed.example", "default"} {
					if !strings.Contains(output.String(), want) {
						t.Fatalf("claim output missing %q:\n%s", want, output.String())
					}
				}
			}
		})
	}
}

func TestDomainStatusFindsOneDomainAndShowsAction(t *testing.T) {
	claimed := authorityv1.Domain{CanonicalDomain: "claimed.example", Id: "domain_1", Kind: "claimed", State: authorityv1.DomainStatePending, RequiredRecords: []authorityv1.DNSRecord{{Name: "claimed.example", Type: "NS", Value: "ns-1.example"}}}
	domains := []authorityv1.Domain{{CanonicalDomain: "other.example", Id: "domain_2"}, claimed}
	for _, value := range []string{"claimed.example", "domain_1"} {
		found, ok := teamDomain(domains, value)
		if !ok || found.Id != claimed.Id {
			t.Fatalf("lookup %q: %#v, %t", value, found, ok)
		}
		var output bytes.Buffer
		if err := writeDomainStatus(&output, found, true); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"tnl domain status", "verification required", "domain_1", "default  yes", "ns-1.example", "add the DNS records"} {
			if !strings.Contains(output.String(), want) {
				t.Fatalf("status missing %q:\n%s", want, output.String())
			}
		}
		if strings.Contains(output.String(), "other.example") {
			t.Fatalf("status included another domain:\n%s", output.String())
		}
	}
	if _, ok := teamDomain(domains, "missing.example"); ok {
		t.Fatal("missing domain resolved")
	}
	for _, test := range []struct {
		state   authorityv1.DomainState
		heading string
		action  string
	}{
		{authorityv1.DomainStatePending, "provisioning", "check again later"},
		{authorityv1.DomainStateFailed, "failed", "team admin"},
		{authorityv1.DomainStateReady, "ready", "ready for public URLs"},
	} {
		domain := claimed
		domain.State = test.state
		domain.RequiredRecords = nil
		var output bytes.Buffer
		if err := writeDomainStatus(&output, domain, false); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), test.heading) || !strings.Contains(output.String(), test.action) || !strings.Contains(output.String(), "default  no") {
			t.Fatalf("status for %s:\n%s", test.state, output.String())
		}
	}
}

func TestDomainDNSRecordBlocksRenderRequiredRecords(t *testing.T) {
	domain := authorityv1.Domain{
		CanonicalDomain: "claimed.example",
		Id:              "domain_0123456789abcdef0123456789abcdef",
		Kind:            "claimed",
		State:           authorityv1.DomainStatePending,
		RequiredRecords: []authorityv1.DNSRecord{
			{Name: "claimed.example", Type: "NS", Value: "ns-1.example"},
			{Name: "claimed.example", Type: "NS", Value: "ns-2.example"},
		},
	}
	details := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "kind", Value: string(domain.Kind)},
		clioutput.Field{Label: "state", Value: string(domain.State)},
		clioutput.Field{Label: "id", Value: domain.Id},
	)}
	details = append(details, domainDNSRecordBlocks(domain.RequiredRecords)...)
	output, err := clioutput.Render(clioutput.Frame{
		Command: "tnl domain list", State: "1 domain", Footer: "* default",
		Blocks: []clioutput.Block{clioutput.Section(domain.CanonicalDomain, details...)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"claimed.example", "pending", "ns-1.example", "ns-2.example"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output does not contain %q:\n%s", want, output)
		}
	}
	if strings.Count(output, "DNS record") != 2 {
		t.Fatalf("output does not contain both DNS record sections:\n%s", output)
	}
}
