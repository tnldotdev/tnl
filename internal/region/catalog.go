// package region owns provider-qualified deployment identities and their
// geographic metadata. daemon configuration, control placement, and publishers
// share this leaf; it does not depend on runtime or authorization owners.
package region

import (
	_ "embed"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
)

type ID string

// Local explicitly makes no claim about provider or geography.
const Local ID = "local"

type Region struct {
	ID        ID      `json:"id"`
	Name      string  `json:"name"`
	Country   string  `json:"country"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

//go:embed catalog.json
var source []byte

var catalog, byID = loadCatalog()

func loadCatalog() ([]Region, map[ID]Region) {
	var data struct {
		Version int `json:"schema_version"`
		Regions []struct {
			IDs []ID `json:"ids"`
			Region
		} `json:"regions"`
	}
	if err := json.Unmarshal(source, &data); err != nil || data.Version != 2 || len(data.Regions) == 0 {
		panic("invalid region catalog")
	}
	index := make(map[ID]Region)
	var regions []Region
	for _, group := range data.Regions {
		if len(group.IDs) == 0 {
			panic("empty provider region group")
		}
		for _, id := range group.IDs {
			r := group.Region
			r.ID = id
			provider, name, qualified := strings.Cut(string(r.ID), ":")
			if !qualified || !validLabel(provider) || !validLabel(name) || r.Name == "" || len(r.Country) != 2 ||
				math.IsNaN(r.Latitude) || math.IsNaN(r.Longitude) || math.IsInf(r.Latitude, 0) || math.IsInf(r.Longitude, 0) ||
				math.Abs(r.Latitude) > 90 || math.Abs(r.Longitude) > 180 {
				panic("invalid provider region")
			}
			if _, duplicate := index[r.ID]; duplicate {
				panic("duplicate provider region")
			}
			index[r.ID] = r
			regions = append(regions, r)
		}
	}
	return regions, index
}

func validLabel(s string) bool {
	if s == "" || len(s) > 64 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return !strings.Contains(s, "--")
}

func All() []Region { return slices.Clone(catalog) }

// Parse accepts a catalog identity, never an unqualified city or provider alias.
func Parse(value string) (ID, bool) {
	id := ID(strings.ToLower(strings.TrimSpace(value)))
	_, known := byID[id]
	return id, known || id == Local
}

func (id ID) Valid() bool {
	parsed, ok := Parse(string(id))
	return ok && parsed == id
}

var ErrPreference = errors.New("use up to eight distinct provider:region preferences from the region catalog, or local")

func Preferences(values []string) ([]string, error) {
	if len(values) > 8 {
		return nil, ErrPreference
	}
	result := make([]string, 0, len(values))
	seen := make(map[ID]bool, len(values))
	for _, value := range values {
		id, ok := Parse(value)
		if !ok || seen[id] {
			return nil, ErrPreference
		}
		seen[id] = true
		result = append(result, string(id))
	}
	return result, nil
}

// Rank orders exact identities first, then geographic fallback from the first
// preference. nearby providers never become the same identity. callers retain
// capacity and stable service-ID tie breakers; local has no geographic rank.
func Rank(preferences []string, candidate ID) int {
	if len(preferences) == 0 {
		return 0
	}
	for i, preferred := range preferences {
		if string(candidate) == preferred {
			return i
		}
	}
	first, located := byID[ID(preferences[0])]
	other, known := byID[candidate]
	if !located || !known {
		return 99999
	}
	a, b := first.Latitude*math.Pi/180, other.Latitude*math.Pi/180
	dLat := (other.Latitude - first.Latitude) * math.Pi / 180
	dLon := (other.Longitude - first.Longitude) * math.Pi / 180
	h := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(a)*math.Cos(b)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 10000 + int(math.Round(12742*math.Asin(math.Sqrt(min(1, h)))))
}
