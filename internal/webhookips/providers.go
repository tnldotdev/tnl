package webhookips

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

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/webhookprovider"
)

const maxCatalogBytes = 16384
const staleLimit = 24 * time.Hour
const maxFreshness = 15 * time.Minute

func Names() []string { return webhookprovider.Names() }

func Valid(name string) bool { return webhookprovider.Valid(name) }

type Source struct {
	Name     string
	Any      bool
	Prefixes []string
	Stale    bool
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
	if !Valid(name) {
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
	cachedSource, cachedErr := parseCatalog(entry.JSON, name)
	if cachedErr == nil && now.Before(entry.ExpiresAt) {
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
		body, err = readCatalog(response, entry, cachedErr == nil)
		if err == nil {
			var source Source
			source, err = parseCatalog(body, name)
			if err == nil {
				fresh := cacheAge(response.Header.Get("Cache-Control"))
				updated := CacheEntry{JSON: body, ETag: response.Header.Get("ETag"), CheckedAt: now, ExpiresAt: now.Add(fresh)}
				if response.StatusCode == http.StatusNotModified {
					updated.ETag = entry.ETag
				}
				if cache == nil || cache.SaveWebhookPolicy(ctx, server, name, updated) == nil {
					return source, nil
				}
				err = errors.New("could not save webhook policy cache")
			}
		}
	}
	if ctx.Err() != nil {
		return Source{}, ctx.Err()
	}
	if cachedErr == nil && now.Sub(entry.CheckedAt) < staleLimit {
		cachedSource.Stale = true
		return cachedSource, nil
	}
	return Source{}, fmt.Errorf("webhook source for %s unavailable: %w", name, err)
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
			seconds, err := strconv.Atoi(text)
			if err == nil && seconds > 0 {
				return min(time.Duration(seconds)*time.Second, maxFreshness)
			}
		}
	}
	return time.Minute
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
