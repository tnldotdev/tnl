package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"encoding/json/v2"

	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"go.yaml.in/yaml/v3"
)

func TestAccessConfigurationRequiresCredentialsUnlessAnonymous(t *testing.T) {
	for _, tc := range []struct {
		input string
		mode  string
		ip    string
	}{
		{`"restricted"`, "restricted", ""},
		{`"anonymous"`, "anonymous", ""},
		{`{"ip":["192.0.2.0/24"]}`, "restricted", "192.0.2.0/24"},
		{`{"mode":"anonymous","ip":["192.0.2.0/24"]}`, "anonymous", "192.0.2.0/24"},
		{`{"ip":["192.0.2.1","192.0.2.1/32","::ffff:192.0.2.1"]}`, "restricted", "192.0.2.1/32"},
		{`{"ip":["192.0.2.7/24","::ffff:192.0.2.9/120"]}`, "restricted", "192.0.2.0/24"},
	} {
		var value Access
		if err := json.Unmarshal([]byte(tc.input), &value); err != nil || value.VisitorMode() != tc.mode {
			t.Fatalf("access %s: %+v, %v", tc.input, value, err)
		}
		if tc.ip != "" && (len(value.IP) != 1 || value.IP[0] != tc.ip) {
			t.Fatalf("IP access %s: %+v", tc.input, value)
		}
	}
	for _, input := range []string{`{"mode":"*"}`, `{"ip":[]}`, `{"ip":["::ffff:192.0.2.1/95"]}`, `{"other":true}`} {
		var value Access
		if err := json.Unmarshal([]byte(input), &value); err == nil {
			t.Fatalf("invalid access %s was accepted", input)
		}
	}
	var yamlValue Access
	if err := yaml.Unmarshal([]byte("mode: anonymous\nip: [192.0.2.0/24]"), &yamlValue); err != nil || yamlValue.VisitorMode() != "anonymous" || len(yamlValue.IP) != 1 {
		t.Fatalf("YAML access: %+v, %v", yamlValue, err)
	}
}

func TestAccessNormalizedPrefixLimit(t *testing.T) {
	for _, count := range []int{256, 257} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			ip := make([]string, count)
			for i := range ip {
				ip[i] = fmt.Sprintf("2001:db8::%x", i)
			}
			ip = append(ip, ip[0], ip[0]+"/128")
			data, err := json.Marshal(map[string]any{"ip": ip})
			if err != nil {
				t.Fatal(err)
			}
			yamlData, err := yaml.Marshal(map[string]any{"ip": ip})
			if err != nil {
				t.Fatal(err)
			}
			var previous []string
			for _, format := range []string{"json", "yaml", "value"} {
				t.Run(format, func(t *testing.T) {
					var access Access
					var err error
					switch format {
					case "json":
						err = json.Unmarshal(data, &access)
					case "yaml":
						err = yaml.Unmarshal(yamlData, &access)
					case "value":
						access.IP = slices.Clone(ip)
						err = access.Validate()
					}
					if count == 257 {
						if err == nil || !errors.Is(err, authorization.ErrIPPrefixLimit) || !strings.Contains(err.Error(), "256 normalized") {
							t.Fatalf("distinct-prefix limit lost its count diagnostic: %v", err)
						}
						return
					}
					if err != nil || len(access.IP) != 256 || access.VisitorMode() != "restricted" || !slices.IsSorted(access.IP) {
						t.Fatalf("256 canonical prefixes plus duplicates = %+v, %v", access, err)
					}
					if previous != nil && !slices.Equal(access.IP, previous) {
						t.Fatal("normalization differs by input format")
					}
					previous = access.IP
				})
			}
		})
	}
}
