package applicationlimits

import (
	"testing"
	"time"
)

func TestDefaultsAndIndependentBurst(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		l := (Limits{}).Defaults(tcp)
		want := Limits{Concurrency: 1024, RateRequests: 1000, RatePer: time.Second, RateBurst: 2000}
		if tcp {
			want.Concurrency = 24
			want.RateRequests = 10
			want.RateBurst = 20
		}
		if l != want {
			t.Fatalf("defaults=%+v, want %+v", l, want)
		}
	}
	l := Limits{Requests: 2, Concurrency: 1, RateRequests: 10, RatePer: time.Minute, RateBurst: 3}
	if !l.Valid() || l.Defaults(true) != l {
		t.Fatal("explicit limits changed")
	}
	for _, l := range []Limits{{RateBurst: 1}, {RateRequests: 1}, {RatePer: time.Second}, {Requests: -1}, {RateRequests: 1, RatePer: time.Second, RateBurst: -1}} {
		if l.Valid() {
			t.Fatalf("invalid limits accepted: %+v", l)
		}
	}
}
