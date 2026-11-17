package visitorcert

import (
	"testing"
	"time"
)

func TestWorkloadIdentityDeadlineUsesExistingCredentialAndAbsoluteBounds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, test := range []struct {
		name     string
		absolute *time.Time
		want     time.Time
	}{
		{"uncapped", nil, now.Add(6 * time.Hour)},
		{"earlier absolute", new(now.Add(time.Minute)), now.Add(time.Minute)},
		{"later absolute", new(now.Add(7 * time.Hour)), now.Add(6 * time.Hour)},
		{"expired absolute", new(now.Add(-time.Second)), now.Add(-time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := WorkloadDeadline(now, test.absolute); !got.Equal(test.want) {
				t.Fatal("credential identity lost the existing absolute bound", got, test.want)
			}
		})
	}
}
