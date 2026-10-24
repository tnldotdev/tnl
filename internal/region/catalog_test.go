package region

import "testing"

func TestCatalogNormalizesProvidersWithoutSharingMutableData(t *testing.T) {
	for _, test := range []struct {
		provider Provider
		name     string
		want     Code
	}{
		{AWS, "us-west-1", "sjc"}, {GCP, "us-west1", "sea"},
		{Azure, "westus", "sjc"}, {Fly, "SJC", "sjc"},
		{AWS, "eu-central-1", "fra"}, {Azure, "australiaeast", "syd"},
	} {
		got, ok := FromProvider(test.provider, test.name)
		if !ok || got != test.want {
			t.Fatalf("%s %s: got %s", test.provider, test.name, got)
		}
	}
	if _, ok := FromProvider(AWS, "us-missing-1"); ok {
		t.Fatal("unknown provider region selected a location")
	}
	entries := All()
	entries[0].Providers[AWS] = "other"
	if got, _ := FromProvider(AWS, "us-west-1"); got != "sjc" {
		t.Fatal("caller changed the catalog's provider mapping")
	}
}

func TestLocationPreferenceAndFallback(t *testing.T) {
	preferred, err := Preferences([]string{"aws:US-WEST-1", "gcp:europe-west3"})
	if err != nil || len(preferred) != 2 || preferred[0] != "sjc" || preferred[1] != "fra" {
		t.Fatal("location normalization lost provider aliases", preferred, err)
	}
	if !(Rank(preferred, "sjc") < Rank(preferred, "fra") && Rank(preferred, "fra") < Rank(preferred, "lax") && Rank(preferred, "lax") < Rank(preferred, "iad") && Rank(preferred, "iad") < Rank(preferred, "")) {
		t.Fatal("exact locality or nearest fallback was lost")
	}
	for _, values := range [][]string{{"sjc", "fly:sjc"}, {"aws:unknown"}, {"nope"}, {"sjc", "sea", "lax", "dfw", "ord", "iad", "lhr", "fra", "sin"}} {
		if _, err := Preferences(values); err != ErrPreference {
			t.Fatal("unrecognized or duplicate preference was accepted", values, err)
		}
	}
	if Rank(nil, "") != 0 {
		t.Fatal("unconfigured location changed load-based placement")
	}
}
