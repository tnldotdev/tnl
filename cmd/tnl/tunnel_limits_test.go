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
	if _, err := parser.Parse([]string{"publish", "web", "--rate-count=3"}); err != nil {
		t.Fatal(err)
	}
	requests, rateRequests, concurrency := 20, 2, 7
	period := config.Duration(time.Minute)
	target := config.Target("3000")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Tunnel:   &config.Tunnel{Limits: &config.Limits{HTTP: &config.WorkLimits{Total: &requests, Rate: &config.Rate{Count: &rateRequests, Per: &period}}}},
		Services: config.Services{"web": {Tunnel: &config.Tunnel{Limits: &config.Limits{HTTP: &config.WorkLimits{Concurrency: &concurrency}}}, Publish: &config.Publish{Target: &target}}},
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
		{"publish", "3000", "--total=0"},
		{"publish", "3000", "--concurrency=-1"},
		{"publish", "3000", "--rate-count=1"},
		{"publish", "3000", "--rate-per=1m"},
		{"publish", "3000", "--rate-count=1", "--rate-per=0s"},
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

func TestTrafficLimitsMergeAndCLIOverride(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"publish", "web", "--traffic-connections=16", "--traffic-upload=4MiB/s"}); err != nil {
		t.Fatal(err)
	}
	connections, count, burst := 32, 20, 40
	period := config.Duration(time.Second)
	upload, download := config.ByteRate("8MiB/s"), config.ByteRate("16MiB/s")
	target := config.Target("3000")
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{
		Tunnel: &config.Tunnel{Limits: &config.Limits{Traffic: &config.TrafficLimits{
			Connections: &connections, Rate: &config.Rate{Count: &count, Per: &period, Burst: &burst},
			Bandwidth: &config.Bandwidth{Upload: &upload, Download: &download},
		}}},
		Services: config.Services{"web": {Publish: &config.Publish{Target: &target}}},
	}}}
	if err := project.applyPublish(&flags.Publish); err != nil {
		t.Fatal(err)
	}
	selected, err := flags.Publish.traffic()
	if err != nil || selected.Connections == nil || *selected.Connections != 16 ||
		selected.Rate == nil || *selected.Rate != 20 || selected.RatePer == nil || *selected.RatePer != "1s" ||
		selected.Burst == nil || *selected.Burst != 40 || selected.UploadBytes == nil || *selected.UploadBytes != 4<<20 ||
		selected.DownloadBytes == nil || *selected.DownloadBytes != 16<<20 {
		t.Fatalf("traffic selection = %+v, %v", selected, err)
	}
}
