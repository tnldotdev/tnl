// package webhookcatalog resolves bounded provider sender policies for control.
package webhookcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/webhookprovider"
)

const maxFeedBytes = 8 << 20
const freshness = 15 * time.Minute
const lastGood = 24 * time.Hour
const retryDelay = 30 * time.Second

var ErrUnknown = errors.New("unknown webhook provider")
var ErrUnavailable = errors.New("webhook provider source unavailable")

type Source struct {
	Kind   string   `json:"kind"`
	Ranges []string `json:"ranges,omitempty"`
}

type Result struct {
	Source Source
	ETag   string
	MaxAge int
}

type cached struct {
	mu         sync.Mutex
	source     Source
	etag       string
	checked    time.Time
	retryAfter time.Time
}

type Catalog struct {
	client      *http.Client
	definitions map[string]definition
	entries     map[string]*cached
	now         func() time.Time
}

func New(client *http.Client) *Catalog { return newCatalog(client, sources) }

func newCatalog(client *http.Client, definitions map[string]definition) *Catalog {
	if client == nil {
		client = http.DefaultClient
	}
	entries := make(map[string]*cached, len(webhookprovider.Names()))
	for _, name := range webhookprovider.Names() {
		entries[name] = &cached{}
	}
	return &Catalog{client: client, definitions: definitions, entries: entries, now: time.Now}
}

// Read returns a validated policy or a bounded last-good copy; it never widens on failure.
func (c *Catalog) Read(ctx context.Context, name string) (Result, error) {
	if !webhookprovider.Valid(name) {
		return Result{}, ErrUnknown
	}
	entry := c.entries[name]
	entry.mu.Lock()
	defer entry.mu.Unlock()
	now := c.now()
	current := func(maxAge int) Result { return Result{Source: entry.source, ETag: entry.etag, MaxAge: maxAge} }
	if !entry.checked.IsZero() && now.Before(entry.checked.Add(freshness)) {
		return current(int(entry.checked.Add(freshness).Sub(now).Seconds())), nil
	}
	if !now.Before(entry.retryAfter) {
		definition := c.definitions[name]
		var source Source
		var err error
		switch {
		case len(definition.static) > 0:
			source, err = ipSource(definition.static)
		case definition.url != "":
			source, err = c.fetch(ctx, name, definition)
		default:
			source = Source{Kind: "*"}
		}
		if err == nil {
			encoded, encodeErr := json.Marshal(struct {
				Source Source `json:"source"`
			}{Source: source})
			if encodeErr != nil {
				return Result{}, encodeErr
			}
			sum := sha256.Sum256(encoded)
			entry.source, entry.etag, entry.checked = source, `"`+hex.EncodeToString(sum[:])+`"`, now
			entry.retryAfter = time.Time{}
			return current(int(freshness.Seconds())), nil
		}
		entry.retryAfter = now.Add(retryDelay)
	}
	if !entry.checked.IsZero() && now.Sub(entry.checked) < lastGood {
		return current(0), nil
	}
	return Result{}, ErrUnavailable
}

func (c *Catalog) fetch(ctx context.Context, name string, definition definition) (Source, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, definition.url, nil)
	if err != nil {
		return Source{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "tnld")
	client := *c.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return Source{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Source{}, fmt.Errorf("provider source returned HTTP %d", response.StatusCode)
	}
	body, err := httpjson.ReadAll(response.Body, maxFeedBytes)
	if err != nil {
		return Source{}, err
	}
	addresses, err := feedAddresses(name, body, definition.field)
	if err != nil {
		return Source{}, err
	}
	return ipSource(addresses)
}

func feedAddresses(name string, body []byte, field string) ([]string, error) {
	switch name {
	case "github", "stripe", "linear":
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
			return nil, errors.New("invalid provider feed")
		}
		var values []string
		if err := json.Unmarshal(fields[field], &values); err != nil {
			return nil, errors.New("invalid provider sender list")
		}
		return values, nil
	case "clerk":
		var regions map[string][]string
		if err := json.Unmarshal(body, &regions); err != nil || len(regions) == 0 || len(regions) > 64 {
			return nil, errors.New("invalid clerk sender regions")
		}
		var values []string
		for _, region := range regions {
			if len(region) == 0 {
				return nil, errors.New("empty clerk sender region")
			}
			values = append(values, region...)
		}
		return values, nil
	case "auth0":
		var document struct {
			Regions map[string]struct {
				IPv4CIDRs []string `json:"ipv4_cidrs"`
			} `json:"regions"`
		}
		if err := json.Unmarshal(body, &document); err != nil || len(document.Regions) == 0 || len(document.Regions) > 64 {
			return nil, errors.New("invalid auth0 sender regions")
		}
		var values []string
		for _, region := range document.Regions {
			if len(region.IPv4CIDRs) == 0 {
				return nil, errors.New("empty auth0 sender region")
			}
			values = append(values, region.IPv4CIDRs...)
		}
		return values, nil
	default:
		return nil, ErrUnknown
	}
}

func ipSource(addresses []string) (Source, error) {
	if len(addresses) == 0 || len(addresses) > 512 {
		return Source{}, errors.New("invalid provider sender count")
	}
	for _, value := range addresses {
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix != prefix.Masked() {
			return Source{}, errors.New("provider prefix has host bits set")
		}
	}
	ranges, err := authorization.CanonicalizeIPPrefixes(addresses)
	if err != nil || len(ranges) != len(addresses) {
		return Source{}, errors.New("invalid provider sender IPs")
	}
	if slices.Contains(ranges, "0.0.0.0/0") || slices.Contains(ranges, "::/0") {
		return Source{}, errors.New("unrestricted provider sender IPs")
	}
	return Source{Kind: "ip_ranges", Ranges: ranges}, nil
}
