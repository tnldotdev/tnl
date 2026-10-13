package trafficlimits

import (
	"strings"
	"testing"
	"time"
)

func TestByteRatesAndOperatorCeilings(t *testing.T) {
	for input, expected := range map[string]int64{"64KiB/s": 64 << 10, "8MiB/s": 8 << 20, "1GiB/s": 1 << 30} {
		actual, err := ParseByteRate(input)
		if err != nil || actual != expected {
			t.Fatalf("%s = %d, %v", input, actual, err)
		}
	}
	for _, input := range []string{"", "0MiB/s", "32KiB/s", "1MB/s", "1 MiB/s", "999999999999GiB/s"} {
		if _, err := ParseByteRate(input); err == nil {
			t.Fatalf("invalid bandwidth %q accepted", input)
		}
	}
	defaults, ceiling := Default(), Ceiling()
	count, period, burst, upload := 90, "1s", 120, int64(16<<20)
	selected, err := (Selection{Rate: &count, RatePer: &period, Burst: &burst, UploadBytes: &upload}).Resolve(defaults, ceiling)
	if err != nil || selected.Rate != 90 || selected.RatePer != time.Second || selected.Burst != 120 ||
		selected.UploadBytes != upload || selected.Connections != defaults.Connections || selected.DownloadBytes != defaults.DownloadBytes {
		t.Fatalf("selected traffic = %+v, %v", selected, err)
	}
	count, period = 200, "2s" // the server compares the sustained rate, not the period's count.
	if _, err := (Selection{Rate: &count, RatePer: &period, Burst: &burst}).Resolve(defaults, ceiling); err != nil {
		t.Fatalf("equivalent per-second ceiling was rejected: %v", err)
	}
	count = 201
	if _, err := (Selection{Rate: &count, RatePer: &period}).Resolve(defaults, ceiling); err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("above-ceiling traffic = %v", err)
	}
	period = "1ns"
	if _, err := (Selection{RatePer: &period}).Resolve(defaults, ceiling); err == nil {
		t.Fatal("unreasonably short rate period was accepted")
	}
}
