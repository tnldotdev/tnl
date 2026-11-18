package publisherenrollment

import (
	"testing"
	"time"
)

func TestLimits(t *testing.T) {
	if got := Default(); got != (Limits{Members: 256, Lifetime: 24 * time.Hour, ProjectPublishers: 256}) {
		t.Fatal("default ceilings changed", got)
	}
	for _, limits := range []Limits{
		Default(), {Members: 100000, Lifetime: 2160 * time.Hour, ProjectPublishers: 100000},
		{Members: MaxMembers, Lifetime: MaxLifetime, ProjectPublishers: MaxMembers},
	} {
		if err := limits.Validate(); err != nil {
			t.Fatal("valid limits rejected", limits, err)
		}
		if !ValidRequest(limits.Members, limits.Lifetime) {
			t.Fatal("request bounds disagree", limits)
		}
	}
	for _, mutate := range []func(*Limits){
		func(l *Limits) { l.Members = 0 }, func(l *Limits) { l.Members = MaxMembers + 1 },
		func(l *Limits) { l.ProjectPublishers = 0 }, func(l *Limits) { l.ProjectPublishers = MaxMembers + 1 },
		func(l *Limits) { l.Lifetime = time.Minute - time.Second },
		func(l *Limits) { l.Lifetime = time.Minute + time.Nanosecond },
		func(l *Limits) { l.Lifetime = MaxLifetime + time.Second },
	} {
		limits := Default()
		mutate(&limits)
		if err := limits.Validate(); err == nil {
			t.Fatal("invalid limits accepted", limits)
		}
	}
}
