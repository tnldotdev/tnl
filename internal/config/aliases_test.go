package config

import (
	"encoding/json"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestAliasDeclarationsArePortableAndServiceScoped(t *testing.T) {
	for _, source := range []string{
		`{"services":{"api":{}},"aliases":{"review":{"service":"api"},"nested":{"service":"api","name":"api.shop"}}}`,
		"services:\n  api: {}\naliases:\n  review:\n    service: api\n  nested:\n    service: api\n    name: api.shop\n",
	} {
		var config TNL
		var err error
		if strings.HasPrefix(source, "{") {
			err = json.Unmarshal([]byte(source), &config)
		} else {
			err = yaml.Unmarshal([]byte(source), &config)
		}
		if err != nil || ValidateTNL(config) != nil || config.Aliases["review"].RelativeName("review") != "review" || config.Aliases["nested"].RelativeName("nested") != "api.shop" {
			t.Fatalf("valid alias declarations rejected: %v", err)
		}
	}
}

func TestAliasFingerprintDistinguishesInheritedAndExplicitEmptyVisitorPolicy(t *testing.T) {
	definition := Alias{Service: "api"}
	_, inherited, err := definition.DefinitionBytes("review")
	if err != nil {
		t.Fatal(err)
	}
	definition.AllowIP = []string{}
	_, explicit, err := definition.DefinitionBytes("review")
	if err != nil || inherited == explicit {
		t.Fatal("explicit visitor-policy override looked like inheritance")
	}
}

func TestAliasExactHostnameHasOneIdentityAndFingerprint(t *testing.T) {
	bare, origin := "review.example.test", "https://review.example.test"
	_, bareHash, err := (Alias{Service: "api", PublicURL: &bare}).DefinitionBytes("review")
	if err != nil {
		t.Fatal(err)
	}
	_, originHash, err := (Alias{Service: "api", PublicURL: &origin}).DefinitionBytes("review")
	if err != nil || bareHash != originHash {
		t.Fatalf("equivalent exact aliases have different hashes: %x, %x, %v", bareHash, originHash, err)
	}
	config := TNL{Services: Services{"api": {}}, Aliases: map[string]Alias{
		"first": {Service: "api", PublicURL: &bare}, "second": {Service: "api", PublicURL: &origin},
	}}
	if err := ValidateAliases(config); err == nil || !strings.Contains(err.Error(), "also used") {
		t.Fatalf("equivalent exact aliases were not detected: %v", err)
	}
}

func TestInvalidAliasDeclarations(t *testing.T) {
	for _, test := range []struct{ name, declaration, want string }{
		{"missing service", `{"review":{"service":"missing"}}`, "not configured"},
		{"invalid key", `{"Review":{"service":"api"}}`, "key must"},
		{"empty name", `{"review":{"service":"api","name":""}}`, "name must"},
		{"uppercase", `{"review":{"service":"api","name":"API.shop"}}`, "name must"},
		{"empty label", `{"review":{"service":"api","name":"api..shop"}}`, "name must"},
		{"wildcard", `{"review":{"service":"api","name":"*.shop"}}`, "name must"},
		{"exclusive name", `{"review":{"service":"api","name":"review","public_url":"https://review.example.test"}}`, "mutually exclusive"},
		{"exclusive domain", `{"review":{"service":"api","domain":"example.test","public_url":"https://review.example.test"}}`, "omit domain"},
		{"URL path", `{"review":{"service":"api","public_url":"https://review.example.test/path"}}`, "without a port"},
		{"mixed IP policy", `{"review":{"service":"api","allow_all_ips":true,"allow_ip":["192.0.2.1"]}}`, "cannot be combined"},
		{"duplicate names", `{"first":{"service":"api","name":"review"},"second":{"service":"api","name":"review"}}`, "also used"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config TNL
			if err := json.Unmarshal([]byte(`{"services":{"api":{}},"aliases":`+test.declaration+`}`), &config); err != nil {
				t.Fatal(err)
			}
			err := ValidateTNL(config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("alias validation = %v, want %q", err, test.want)
			}
		})
	}
	var duplicateInherited TNL
	if err := json.Unmarshal([]byte(`{"tunnel":{"domain":"custom.example.test"},"services":{"api":{},"web":{"tunnel":{"domain":"custom.example.test"}}},"aliases":{"first":{"service":"api","name":"review"},"second":{"service":"web","name":"review"}}}`), &duplicateInherited); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTNL(duplicateInherited); err == nil {
		t.Fatal("inherited domains hid a duplicate alias hostname")
	}
}
