// package region owns the validated, provider-neutral location codes shared
// by daemon registration, control placement, and client preferences. hosting
// provider names are inputs to normalization, never placement identities.
package region

import (
	_ "embed"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
)

type Code string
type Provider string

// Local is the explicit region for a self-hosted server with no mapped site.
// it does not assert a geographic location or match a provider region.
const Local Code = "local"

const (
	AWS          Provider = "aws"
	GCP          Provider = "gcp"
	Azure        Provider = "azure"
	Fly          Provider = "fly"
	DigitalOcean Provider = "digitalocean"
	Hetzner      Provider = "hetzner"
	Linode       Provider = "linode"
	Vultr        Provider = "vultr"
	OCI          Provider = "oci"
	Scaleway     Provider = "scaleway"
)

type Location struct {
	Code      Code                  `json:"code"`
	Name      string                `json:"name"`
	Country   string                `json:"country"`
	Latitude  float64               `json:"latitude"`
	Longitude float64               `json:"longitude"`
	Providers map[Provider][]string `json:"providers"`
}

type catalog struct {
	Version   int        `json:"schema_version"`
	Locations []Location `json:"locations"`
}

//go:embed catalog.json
var source []byte

var locations, byCode, byProvider = loadCatalog()

func loadCatalog() ([]Location, map[Code]Location, map[string]Code) {
	var data catalog
	if err := json.Unmarshal(source, &data); err != nil || data.Version != 1 || len(data.Locations) == 0 {
		panic("invalid region catalog")
	}
	codes := make(map[Code]Location, len(data.Locations))
	providers := make(map[string]Code)
	for _, location := range data.Locations {
		if !validLocationCode(location.Code) || location.Name == "" || strings.TrimSpace(location.Name) != location.Name ||
			len(location.Country) != 2 || location.Country[0] < 'A' || location.Country[0] > 'Z' || location.Country[1] < 'A' || location.Country[1] > 'Z' ||
			len(location.Providers) == 0 || math.IsNaN(location.Latitude) || math.IsNaN(location.Longitude) ||
			math.IsInf(location.Latitude, 0) || math.IsInf(location.Longitude, 0) || math.Abs(location.Latitude) > 90 || math.Abs(location.Longitude) > 180 {
			panic("invalid region catalog location")
		}
		if _, exists := codes[location.Code]; exists {
			panic("duplicate region code")
		}
		codes[location.Code] = location
		for provider, names := range location.Providers {
			if !validProvider(provider) || len(names) == 0 {
				panic("invalid provider region")
			}
			for _, name := range names {
				if !validProviderRegion(name) {
					panic("invalid provider region")
				}
				key := string(provider) + ":" + name
				if _, exists := providers[key]; exists {
					panic("duplicate provider region")
				}
				providers[key] = location.Code
			}
		}
	}
	return data.Locations, codes, providers
}

func validProvider(value Provider) bool {
	switch value {
	case AWS, GCP, Azure, Fly, DigitalOcean, Hetzner, Linode, Vultr, OCI, Scaleway:
		return true
	default:
		return false
	}
}

func validLocationCode(value Code) bool {
	if len(value) != 3 {
		return false
	}
	for _, letter := range value {
		if letter < 'a' || letter > 'z' {
			return false
		}
	}
	return true
}

func validProviderRegion(value string) bool {
	if value == "" {
		return false
	}
	for index, letter := range value {
		if letter >= 'a' && letter <= 'z' || letter >= '0' && letter <= '9' {
			continue
		}
		if letter != '-' || index == 0 || index == len(value)-1 || value[index-1] == '-' {
			return false
		}
	}
	return true
}

// All returns independent copies so callers cannot change placement data.
func All() []Location {
	copy := make([]Location, len(locations))
	for index, location := range locations {
		copy[index] = location
		copy[index].Providers = make(map[Provider][]string, len(location.Providers))
		for provider, names := range location.Providers {
			copy[index].Providers[provider] = slices.Clone(names)
		}
	}
	return copy
}

// Parse accepts only a stable tnl code; provider-specific inputs use FromProvider.
func Parse(value string) (Code, bool) {
	code := Code(strings.ToLower(strings.TrimSpace(value)))
	if code == Local {
		return code, true
	}
	_, found := byCode[code]
	return code, found
}

func FromProvider(provider Provider, name string) (Code, bool) {
	code, found := byProvider[string(provider)+":"+strings.ToLower(strings.TrimSpace(name))]
	return code, found
}

var ErrPreference = errors.New("invalid location preference")

// Preferences normalizes explicit tnl codes and provider:region inputs in
// caller order. unknown or duplicate names fail instead of silently selecting
// a different locality. an empty list preserves load-based placement.
func Preferences(values []string) ([]Code, error) {
	if len(values) > 8 {
		return nil, ErrPreference
	}
	if len(values) == 0 {
		return nil, nil
	}
	result := make([]Code, 0, len(values))
	seen := make(map[Code]bool, len(values))
	for _, value := range values {
		var code Code
		var found bool
		if provider, name, qualified := strings.Cut(strings.TrimSpace(value), ":"); qualified {
			code, found = FromProvider(Provider(strings.ToLower(provider)), name)
		} else {
			code, found = Parse(value)
		}
		if !found || seen[code] {
			return nil, ErrPreference
		}
		seen[code] = true
		result = append(result, code)
	}
	return result, nil
}

// Rank favors an exact preferred code, then the nearest known fallback to
// the first preference. unknown/unconfigured sites sort after known sites.
// callers retain capacity and stable-identity tie breakers.
func Rank(preferences []Code, candidate Code) int {
	if len(preferences) == 0 {
		return 0
	}
	for index, code := range preferences {
		if candidate == code {
			return index
		}
	}
	first, exists := byCode[preferences[0]]
	other, known := byCode[candidate]
	if !exists || !known {
		return 99999
	}
	a, b := first.Latitude*math.Pi/180, other.Latitude*math.Pi/180
	dLat := (other.Latitude - first.Latitude) * math.Pi / 180
	dLon := (other.Longitude - first.Longitude) * math.Pi / 180
	h := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(a)*math.Cos(b)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 10000 + int(math.Round(12742*math.Asin(math.Sqrt(min(1, h)))))
}
