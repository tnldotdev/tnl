package main

import (
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestPublisherLimitsMergeAndFlagPrecedence(t *testing.T) {
	t.Setenv("TNL_CONCURRENCY", "4")
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"publish", "web", "--rate-requests=3"}); err != nil {
		t.Fatal(err)
	}
	requests, rateRequests, concurrency := 20, 2, 7
	period := config.Duration(time.Minute)
	target := config.Target("3000")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Tunnel:   &config.Tunnel{Limits: &config.Limits{Requests: &requests, Rate: &config.Rate{Requests: &rateRequests, Per: &period}}},
		Services: config.Services{"web": {Tunnel: &config.Tunnel{Limits: &config.Limits{Concurrency: &concurrency}}, Publish: &config.Publish{Target: &target}}},
	}}}
	if err := project.applyPublish(&flags.Publish); err != nil {
		t.Fatal(err)
	}
	limits := flags.Publish.limits()
	if limits.Requests != 20 || limits.RateRequests != 3 || limits.RatePer != time.Minute || limits.Concurrency != 4 {
		t.Fatalf("limits = %+v", limits)
	}
}

func TestPublisherLimitsRequirePositivePairedRate(t *testing.T) {
	for _, args := range [][]string{
		{"publish", "3000", "--requests=0"},
		{"publish", "3000", "--concurrency=-1"},
		{"publish", "3000", "--rate-requests=1"},
		{"publish", "3000", "--rate-per=1m"},
		{"publish", "3000", "--rate-requests=1", "--rate-per=0s"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err != nil {
			t.Fatal(err)
		}
		if err := (projectConfiguration{}).applyPublish(&flags.Publish); err == nil {
			t.Fatalf("invalid limits %v were accepted", args)
		}
	}
}

func TestRetiredRequestLimitFlagIsNotAccepted(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"publish", "3000", "--request-limit=5"}); err == nil {
		t.Fatal("retired request-limit flag was accepted")
	}
}
