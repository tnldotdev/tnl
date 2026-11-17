package webhooksource

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const maxCatalogBytes = 16384
const staleLimit = ippolicy.ProviderLastGoodFor
const maxFreshness = ippolicy.ProviderFreshFor
const refreshRetry = 30 * time.Second

type Source struct {
	Name                  string
	Any                   bool
	Prefixes              []string
	Stale                 bool
	Revision              string
	RefreshAt, ValidUntil time.Time
}

type cachedCatalog struct {
	Body      json.RawMessage `json:"body"`
	CheckedAt time.Time       `json:"provider_checked_at"`
}

type CacheEntry struct {
	JSON                 []byte
	ETag                 string
	CheckedAt, ExpiresAt time.Time
}

type Cache interface {
	CachedWebhookPolicy(context.Context, string, string) (CacheEntry, error)
	SaveWebhookPolicy(context.Context, string, string, CacheEntry) error
}

// Resolve reads the selected server's catalog and its bounded last-good cache.
func Resolve(ctx context.Context, cache Cache, server, name string) (Source, error) {
	server, err := naming.CanonicalControlURL(server)
	if err != nil {
		return Source{}, fmt.Errorf("invalid control URL for webhook source: %w", err)
	}
	client := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("webhook catalog redirected")
	}}
	return resolve(ctx, client, cache, server, name, time.Now())
}

func resolve(ctx context.Context, client *http.Client, cache Cache, server, name string, now time.Time) (Source, error) {
	started := time.Now()
	if !controlv1.WebhookProvider(name).Valid() {
		return Source{}, fmt.Errorf("unknown webhook provider %q", name)
	}
	// custom has no provider-managed sender addresses or upstream dependency.
	if name == "custom" {
		return Source{Name: name, Any: true}, nil
	}
	var entry CacheEntry
	if cache != nil {
		cached, err := cache.CachedWebhookPolicy(ctx, server, name)
		if err == nil {
			entry = cached
		} else if !errors.Is(err, sql.ErrNoRows) {
			return Source{}, fmt.Errorf("read webhook policy cache: %w", err)
		}
	}
	var catalog cachedCatalog
	cachedErr := json.Unmarshal(entry.JSON, &catalog)
	cachedSource, sourceErr := parseCatalog(catalog.Body, name)
	if cachedErr == nil {
		cachedErr = sourceErr
	}
	if cachedErr == nil && (catalog.CheckedAt.IsZero() || entry.CheckedAt.IsZero() || entry.CheckedAt.After(now) || entry.ETag == "" ||
		!entry.ExpiresAt.After(entry.CheckedAt) || entry.ExpiresAt.After(entry.CheckedAt.Add(maxFreshness))) {
		cachedErr = errors.New("invalid webhook policy cache window")
	}
	bind := func(source Source, checked, refresh time.Time, revision string, at time.Time) Source {
		source.Revision, source.ValidUntil = revision, checked.Add(staleLimit)
		source.Stale = !at.Before(checked.Add(maxFreshness))
		source.RefreshAt = refresh
		if !at.Before(refresh) {
			source.RefreshAt = minTime(at.Add(refreshRetry), source.ValidUntil)
		}
		return source
	}
	if cachedErr == nil && now.Before(entry.ExpiresAt) && now.Before(entry.CheckedAt.Add(staleLimit)) {
		cachedSource = bind(cachedSource, entry.CheckedAt, entry.ExpiresAt, entry.ETag, now)
		return cachedSource, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/v1/webhook-providers/"+name+"/source", nil)
	if err != nil {
		return Source{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "tnl")
	if cachedErr == nil && entry.ETag != "" {
		request.Header.Set("If-None-Match", entry.ETag)
	}
	response, err := client.Do(request)
	if err == nil {
		var body []byte
		bodyCache := entry
		bodyCache.JSON = catalog.Body
		body, err = readCatalog(response, bodyCache, cachedErr == nil)
		if err == nil {
			var source Source
			source, err = parseCatalog(body, name)
			if err == nil {
				window, windowErr := ippolicy.ReadProviderWindow(response.Header)
				completed := now.Add(time.Since(started))
				age, ageErr := catalogAge(response.Header.Get("Age"))
				checked, freshUntil, _, localErr := window.Local(now.Add(-age), completed)
				revision := response.Header.Get("ETag")
				if windowErr != nil || ageErr != nil || localErr != nil || revision == "" || len(revision) > 128 ||
					response.StatusCode == http.StatusNotModified && revision != entry.ETag {
					err = errors.New("catalog returned invalid freshness or revision")
				} else if cachedErr == nil && window.CheckedAt.Before(catalog.CheckedAt) {
					err = errors.New("catalog returned an older provider check")
				} else {
					if cachedErr == nil && window.CheckedAt.Equal(catalog.CheckedAt) {
						checked = minTime(checked, entry.CheckedAt)
						freshUntil = checked.Add(maxFreshness)
					}
					expires := minTime(freshUntil, now.Add(max(0, cacheAge(response.Header.Get("Cache-Control"))-age)))
					encoded, encodeErr := json.Marshal(cachedCatalog{Body: body, CheckedAt: window.CheckedAt})
					updated := CacheEntry{JSON: encoded, ETag: revision, CheckedAt: checked, ExpiresAt: expires}
					if encodeErr == nil && len(encoded) <= maxCatalogBytes && updated.ExpiresAt.After(checked) &&
						completed.Before(checked.Add(staleLimit)) &&
						(cache == nil || cache.SaveWebhookPolicy(ctx, server, name, updated) == nil) {
						return bind(source, checked, expires, revision, completed), nil
					}
					err = errors.New("could not save or use webhook policy cache")
				}
			}
		}
	}
	if ctx.Err() != nil {
		return Source{}, errors.Join(err, ctx.Err())
	}
	completed := now.Add(time.Since(started))
	if cachedErr == nil && completed.Before(entry.CheckedAt.Add(staleLimit)) {
		cachedSource = bind(cachedSource, entry.CheckedAt, completed.Add(refreshRetry), entry.ETag, completed)
		cachedSource.Stale = true
		return cachedSource, nil
	}
	return Source{}, fmt.Errorf("webhook source for %s unavailable: %w", name, err)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func readCatalog(response *http.Response, cached CacheEntry, validCache bool) ([]byte, error) {
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNotModified:
		if validCache {
			return cached.JSON, nil
		}
		return nil, errors.New("catalog returned 304 without cached source")
	case http.StatusOK:
		return httpjson.ReadAll(response.Body, maxCatalogBytes)
	default:
		return nil, fmt.Errorf("catalog returned HTTP %d", response.StatusCode)
	}
}

func cacheAge(value string) time.Duration {
	for _, directive := range strings.Split(value, ",") {
		directive = strings.TrimSpace(directive)
		if text, ok := strings.CutPrefix(directive, "max-age="); ok {
			seconds, err := strconv.ParseUint(text, 10, 64)
			if err == nil {
				if seconds >= uint64(maxFreshness/time.Second) {
					return maxFreshness
				}
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return time.Minute
}

// http caches may reuse a response whose observation headers are unchanged.
// spend their age too; integer Age values can omit a fraction of a second.
func catalogAge(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	seconds, err := strconv.ParseUint(value, 10, 32)
	if err != nil || seconds >= uint64(staleLimit/time.Second) {
		return 0, errors.New("invalid catalog response age")
	}
	return (time.Duration(seconds) + 1) * time.Second, nil
}

func parseCatalog(body []byte, name string) (Source, error) {
	if len(body) == 0 || len(body) > maxCatalogBytes {
		return Source{}, errors.New("catalog returned no usable source")
	}
	var document struct {
		Source struct {
			Kind   string   `json:"kind"`
			Ranges []string `json:"ranges"`
		} `json:"source"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Source{}, fmt.Errorf("invalid webhook catalog JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Source{}, errors.New("catalog returned trailing JSON")
	}
	source := Source{Name: name}
	switch document.Source.Kind {
	case "*":
		if document.Source.Ranges != nil {
			return Source{}, errors.New("unrestricted source also supplied ranges")
		}
		source.Any = true
	case "ip_ranges":
		if len(document.Source.Ranges) == 0 || len(document.Source.Ranges) > 512 {
			return Source{}, errors.New("catalog returned no webhook IPs")
		}
		prefixes, err := authorization.CanonicalizeIPPrefixes(document.Source.Ranges)
		if err != nil || len(prefixes) != len(document.Source.Ranges) {
			return Source{}, errors.New("catalog returned invalid or duplicate IPs")
		}
		for _, prefix := range prefixes {
			if prefix == "0.0.0.0/0" || prefix == "::/0" {
				return Source{}, errors.New("catalog returned a prefix allowing every IP")
			}
		}
		for _, prefix := range document.Source.Ranges {
			parsed, err := netip.ParsePrefix(prefix)
			if err != nil || parsed.Masked().String() != prefix {
				return Source{}, errors.New("catalog returned a noncanonical IP prefix")
			}
		}
		source.Prefixes = prefixes
	default:
		return Source{}, errors.New("unknown webhook source kind")
	}
	return source, nil
}
