package webhookips

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/httpjson"
)

const maxProviderResponseBytes = 8 << 20

type provider struct {
	url   string
	field string
}

var providers = map[string]provider{
	"github": {url: "https://api.github.com/meta", field: "hooks"},
	"stripe": {url: "https://stripe.com/files/ips/ips_webhooks.json", field: "WEBHOOKS"},
}

// Source records the distinct, canonical webhook prefixes published by one provider.
type Source struct {
	Name     string
	Prefixes []string
}

func Names() []string {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func Valid(name string) bool {
	_, found := providers[name]
	return found
}

// Resolve reads the selected providers once, before a public URL is published.
func Resolve(ctx context.Context, names []string) ([]Source, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("webhook IP source redirected")
		},
	}
	return resolve(ctx, client, providers, names)
}

func resolve(ctx context.Context, client *http.Client, catalog map[string]provider, names []string) ([]Source, error) {
	sources := make([]Source, 0, len(names))
	seenNames := make(map[string]bool, len(names))
	for _, name := range names {
		definition, found := catalog[name]
		if !found {
			return nil, fmt.Errorf("unknown webhook IP provider %q", name)
		}
		if seenNames[name] {
			return nil, fmt.Errorf("duplicate webhook IP provider %q", name)
		}
		seenNames[name] = true
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, definition.url, nil)
		if err != nil {
			return nil, fmt.Errorf("read %s webhook IPs: %w", name, err)
		}
		request.Header.Set("Accept", "application/json")
		if name == "github" {
			request.Header.Set("User-Agent", "tnl")
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("read %s webhook IPs: %w", name, err)
		}
		prefixes, err := parseResponse(response, definition.field)
		if err != nil {
			return nil, fmt.Errorf("read %s webhook IPs: %w", name, err)
		}
		sources = append(sources, Source{Name: name, Prefixes: prefixes})
	}
	slices.SortFunc(sources, func(a, b Source) int { return cmp.Compare(a.Name, b.Name) })
	return sources, nil
}

func parseResponse(response *http.Response, field string) ([]string, error) {
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("source returned HTTP %d", response.StatusCode)
	}
	data, err := httpjson.ReadAll(response.Body, maxProviderResponseBytes)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, errors.New("source returned invalid JSON")
	}
	var addresses []string
	if err := json.Unmarshal(fields[field], &addresses); err != nil || len(addresses) == 0 {
		return nil, errors.New("source returned no webhook IPs")
	}
	prefixes := make([]string, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		canonical, err := authorization.CanonicalizeIPPrefixes([]string{address})
		if err != nil {
			return nil, fmt.Errorf("source returned invalid IP prefix %q", address)
		}
		prefix := canonical[0]
		if prefix == "0.0.0.0/0" || prefix == "::/0" {
			return nil, errors.New("source returned a prefix allowing every IP")
		}
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}
	slices.Sort(prefixes)
	return prefixes, nil
}
