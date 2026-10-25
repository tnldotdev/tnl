package region

import "testing"

func TestCatalogNormalizesProvidersWithoutSharingMutableData(t *testing.T) {
	for _, test := range []struct {
		provider Provider
		name     string
		want     Code
	}{
		{AWS, "us-west-1", "sjc"}, {GCP, "us-west1", "pdx"},
		{Azure, "westus", "sjc"}, {Fly, "SJC", "sjc"},
		{AWS, "eu-central-1", "fra"}, {Azure, "australiaeast", "syd"},
		{AWS, "us-east-2", "cmh"}, {GCP, "us-central1", "cbl"},
		{DigitalOcean, "nyc3", "nyc"}, {DigitalOcean, "sfo2", "sfo"},
		{Hetzner, "fsn1", "fsn"}, {Linode, "br-gru", "gru"},
		{Vultr, "sao", "gru"}, {OCI, "sa-saopaulo-1", "gru"},
		{Scaleway, "fr-par", "cdg"}, {OCI, "ap-singapore-2", "sin"},
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
	entries[0].Providers[AWS][0] = "other"
	entries[0].Name = "other"
	if got, _ := FromProvider(AWS, "us-west-1"); got != "sjc" {
		t.Fatal("caller changed the catalog's provider mapping")
	}
	if first := All()[0]; first.Name != "San Jose" || first.Providers[AWS][0] != "us-west-1" {
		t.Fatal("caller changed the returned location or provider aliases")
	}
	if got, ok := Parse(" GRU "); !ok || got != "gru" {
		t.Fatal("South America location is not available by its tnl code")
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
	if codes, err := Preferences([]string{"OCI:SA-SAOPAULO-1"}); err != nil || len(codes) != 1 || codes[0] != "gru" {
		t.Fatal("additional provider preference did not normalize", codes, err)
	}
	for _, values := range [][]string{{"sjc", "fly:sjc"}, {"oci:sa-saopaulo-1", "vultr:sao"}, {"aws:unknown"}, {"nope"}, {"sjc", "sea", "lax", "dfw", "ord", "iad", "lhr", "fra", "sin"}} {
		if _, err := Preferences(values); err != ErrPreference {
			t.Fatal("unrecognized or duplicate preference was accepted", values, err)
		}
	}
	if Rank(nil, "") != 0 {
		t.Fatal("unconfigured location changed load-based placement")
	}
}
