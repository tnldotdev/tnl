package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestReadyAccessSummaryUsesEffectivePolicyAndSharedRenderer(t *testing.T) {
	for _, test := range []struct {
		name string
		info publisher.AccessInfo
		want []string
	}{
		{name: "ordinary publish", info: publisher.AccessInfo{BrowserSignInAvailable: true, PublicURLScope: controlv1.Member, AllowedIPPrefixes: []string{"2001:db8::/64", "192.0.2.1/32"}}, want: []string{"IP access", "192.0.2.1/32, 2001:db8::/64", "owning member", "not configured"}},
		{name: "shared app", info: publisher.AccessInfo{BrowserSignInAvailable: true, PublicURLScope: controlv1.Shared}, want: []string{"all IPs", "team admins and owners", "not configured"}},
		{name: "team preview", info: publisher.AccessInfo{BrowserSignInAvailable: true, PublicURLScope: controlv1.Member, PreviewID: "pv_private", TeamAccessEnabled: new(true)}, want: []string{"owning member", "current team members; preview-wide"}},
		{name: "disabled team grant", info: publisher.AccessInfo{BrowserSignInAvailable: true, PublicURLScope: controlv1.Member, PreviewID: "pv_private", TeamAccessEnabled: new(false)}, want: []string{"owning member", "disabled"}},
		{name: "stale grant", info: publisher.AccessInfo{BrowserSignInAvailable: true, PublicURLScope: controlv1.Member, PreviewID: "pv_private"}, want: []string{"owning member", "unavailable"}},
		{name: "no browser login", info: publisher.AccessInfo{PublicURLScope: controlv1.Shared, TeamAccessEnabled: new(true)}, want: []string{"all IPs", "unavailable"}},
		{name: "required feedback", info: publisher.AccessInfo{BrowserSignInAvailable: true, PublicURLScope: controlv1.Member, FeedbackEnabled: true, FeedbackRequireSignIn: new(true)}, want: []string{"feedback sign-in", "required"}},
		{name: "optional feedback", info: publisher.AccessInfo{PublicURLScope: controlv1.Member, FeedbackEnabled: true, FeedbackRequireSignIn: new(false)}, want: []string{"feedback sign-in", "optional"}},
		{name: "unknown feedback policy", info: publisher.AccessInfo{PublicURLScope: controlv1.Member, FeedbackEnabled: true}, want: []string{"feedback sign-in", "unavailable"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			output, err := newPublishOutput(publishOutputHuman, "tnl publish", io.Discard, &stderr, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := output.starting("tun_private", "http://127.0.0.1:3000"); err != nil {
				t.Fatal(err)
			}
			if err := output.currentIP("198.51.100.7"); err != nil {
				t.Fatal(err)
			}
			if err := output.ready("https://app.example", 1, &test.info); err != nil {
				t.Fatal(err)
			}
			text := stderr.String()
			if !strings.HasPrefix(text, "+--[ tnl publish ]-- ready ") || strings.Contains(text, "198.51.100.7") || strings.Contains(text, "pv_private") || strings.Contains(text, "tun_private") {
				t.Fatalf("ready policy snapshot = %s", text)
			}
			for _, want := range test.want {
				if !strings.Contains(text, want) {
					t.Fatalf("ready summary missing %q: %s", want, text)
				}
			}
			if !test.info.BrowserSignInAvailable && (strings.Contains(text, "owning member") || strings.Contains(text, "team admins and owners") || strings.Contains(text, "current team members")) {
				t.Fatal("ready summary claims unavailable browser access")
			}
			for _, line := range strings.Split(text, "\n") {
				if len(line) > 72 || strings.ContainsRune(line, '\x1b') {
					t.Fatalf("invalid frame line: %q", line)
				}
			}
		})
	}
}

func TestReadyAccessSummaryDoesNotChangeNDJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output, err := newPublishOutput(publishOutputNDJSON, "tnl publish", &stdout, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	info := publisher.AccessInfo{AllowedIPPrefixes: []string{"192.0.2.1/32"}, BrowserSignInAvailable: true, PublicURLScope: controlv1.Member, PreviewID: "pv_private", TeamAccessEnabled: new(true), FeedbackEnabled: true, FeedbackRequireSignIn: new(true)}
	if err := output.ready("https://app.example", 7, &info); err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if len(event) != 6 || event["schema_version"] != float64(1) || event["type"] != "ready" || event["publish_run_number"] != float64(7) || event["url"] != "https://app.example" || stderr.Len() != 0 {
		t.Fatalf("NDJSON changed: %s", stdout.String())
	}
}
