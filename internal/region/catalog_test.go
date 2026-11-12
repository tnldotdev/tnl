package region

import (
	"errors"
	"slices"
	"testing"
)

func TestProviderIdentity(t *testing.T) {
	values, err := Preferences([]string{"AWS:US-WEST-1", "fly:sjc"})
	if err != nil || !slices.Equal(values, []string{"aws:us-west-1", "fly:sjc"}) {
		t.Fatal(values, err)
	}
	for _, invalid := range [][]string{{"sjc"}, {"us-west-1"}, {"aws:sjc"}, {"fly:us-west-1"}, {"unknown:sjc"}, {"aws:us-west-1", "AWS:US-WEST-1"}, {""}} {
		if _, err := Preferences(invalid); !errors.Is(err, ErrPreference) {
			t.Fatal("invalid preference accepted", invalid, err)
		}
	}
	if ID("AWS:US-WEST-1").Valid() || !Local.Valid() || !ID("gcp:us-west1").Valid() {
		t.Fatal("canonical validation failed")
	}
	entries := All()
	entries[0].ID = "other"
	if All()[0].ID == "other" {
		t.Fatal("catalog is mutable")
	}
}

func TestRank(t *testing.T) {
	prefs := []string{"aws:us-west-1", "fly:gru"}
	ordered := []ID{"aws:us-west-1", "fly:gru", "fly:sjc", "aws:us-east-1", Local}
	for i := 1; i < len(ordered); i++ {
		if Rank(prefs, ordered[i-1]) >= Rank(prefs, ordered[i]) {
			t.Fatal("exact preference or proximity lost", ordered)
		}
	}
	if Rank(nil, Local) != 0 || Rank([]string{"local"}, "fly:sjc") != 99999 {
		t.Fatal("unlocated selection asserted geography")
	}
	if _, err := Preferences(make([]string, 9)); !errors.Is(err, ErrPreference) {
		t.Fatal("unbounded preferences accepted")
	}
}
