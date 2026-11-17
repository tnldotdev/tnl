package integrations

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/webhooksource"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
)

const maxWebhookBody = 8 << 20
const maxWebhookReceivers = 32

func DefinitionBytes(definition config.Webhook) ([]byte, [32]byte, error) {
	return definition.DefinitionBytes()
}

type webhookEndpoint struct {
	name        string
	definition  config.Webhook
	digest      [32]byte
	prefixes    []netip.Prefix
	any         bool
	unavailable bool
	stale       bool
	validUntil  time.Time
}

type Webhooks struct {
	state            *clientstate.Database
	server, hostname string
	group            clientstate.IntegrationScope
	paths            map[string]webhookEndpoint
	mu               sync.RWMutex
	refreshMu        sync.Mutex
	sources          map[string]webhooksource.Source
	resolve          func(context.Context, webhooksource.Cache, string, string) (webhooksource.Source, error)
	now              func() time.Time
	ingressIPs       []string
	ingressAny       bool
	// report contains only endpoint/tunnel identifiers and fixed failure reasons.
	report func(string, string, string)
	// OnReceiverResponse runs after a selected local service returns HTTP headers.
	OnReceiverResponse func(string)
}

func NewWebhooks(ctx context.Context, state *clientstate.Database, server string, group clientstate.IntegrationScope, hostname string, definitions map[string]config.Webhook, report func(string, string, string)) (*Webhooks, []string, error) {
	return newWebhooks(ctx, state, server, group, hostname, definitions, report, webhooksource.Resolve)
}

func newWebhooks(ctx context.Context, state *clientstate.Database, server string, group clientstate.IntegrationScope, hostname string, definitions map[string]config.Webhook, report func(string, string, string), resolve func(context.Context, webhooksource.Cache, string, string) (webhooksource.Source, error)) (*Webhooks, []string, error) {
	if err := group.Validate(); err != nil {
		return nil, nil, err
	}
	services := config.Services{}
	providers := map[string]bool{}
	for _, definition := range definitions {
		if definition.Service != "" {
			services[definition.Service] = config.Service{Public: new(true)}
		}
		if definition.SourceIPs == nil {
			providers[definition.Provider] = true
		}
	}
	if err := config.ValidateTNL(config.TNL{Services: services, Webhooks: definitions}); err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	slices.Sort(names)
	sources := map[string]webhooksource.Source{}
	for _, name := range names {
		source, err := resolve(ctx, state, server, name)
		if err != nil {
			continue
		}
		sources[name] = source
	}
	handler := &Webhooks{state: state, server: server, group: group, hostname: hostname, paths: map[string]webhookEndpoint{},
		report: report, sources: sources, resolve: resolve, now: time.Now}
	for name, definition := range definitions {
		_, digest, err := DefinitionBytes(definition)
		if err != nil {
			return nil, nil, err
		}
		definition.Methods = slices.Clone(definition.Methods)
		definition.SourceIPs = slices.Clone(definition.SourceIPs)
		handler.paths[definition.Path] = webhookEndpoint{name: name, definition: definition, digest: digest}
	}
	paths, prefixes, any, err := webhookPolicies(handler.paths, sources, handler.now())
	if err != nil {
		return nil, nil, err
	}
	handler.paths, handler.ingressIPs, handler.ingressAny = paths, slices.Clone(prefixes), any
	for _, endpoint := range paths {
		if endpoint.unavailable {
			handler.failure(endpoint.name, "provider catalog", "source policy unavailable")
		}
	}
	return handler, prefixes, nil
}

func webhookPolicies(paths map[string]webhookEndpoint, sources map[string]webhooksource.Source, now time.Time) (map[string]webhookEndpoint, []string, bool, error) {
	current := make(map[string]webhookEndpoint, len(paths))
	union := map[string]bool{}
	allowAll := false
	for path, original := range paths {
		definition := original.definition
		endpoint := webhookEndpoint{name: original.name, definition: definition, digest: original.digest}
		prefixes := slices.Clone(definition.SourceIPs)
		if definition.SourceIPs == nil {
			source, found := sources[definition.Provider]
			if !found || definition.Provider != "custom" && !now.Before(source.ValidUntil) {
				endpoint.unavailable = true
			} else {
				endpoint.any = source.Any
				endpoint.stale = source.Stale
				endpoint.validUntil = source.ValidUntil
				prefixes = source.Prefixes
			}
		}
		allowAll = allowAll || endpoint.any
		for _, value := range prefixes {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, addressErr := netip.ParseAddr(value)
				if addressErr != nil {
					return nil, nil, false, fmt.Errorf("invalid webhook IP prefix: %w", err)
				}
				prefix = netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen())
			}
			endpoint.prefixes = append(endpoint.prefixes, prefix)
			union[prefix.String()] = true
		}
		current[path] = endpoint
	}
	prefixes := []string{}
	if !allowAll {
		for prefix := range union {
			prefixes = append(prefixes, prefix)
		}
		slices.Sort(prefixes)
	}
	return current, prefixes, allowAll, nil
}

// HasAvailablePolicy distinguishes an explicitly unrestricted source from an
// empty union of unavailable endpoints. an empty union must not remove IP limits.
func (h *Webhooks) HasAvailablePolicy() bool {
	now := h.now()
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, endpoint := range h.paths {
		if !endpoint.unavailable && (endpoint.validUntil.IsZero() || now.Before(endpoint.validUntil)) {
			return true
		}
	}
	return false
}

// RefreshPolicies is called by the existing integration publisher tick. requests
// never wait for a feed fetch and capture their policy before reading any body.
// tightening is installed locally even if the coarse service-union write fails;
// that old union can only cause additional denials, not grant path access.
func (h *Webhooks) RefreshPolicies(ctx context.Context, install func(context.Context, []string) error) error {
	h.refreshMu.Lock()
	defer h.refreshMu.Unlock()
	now := h.now()
	h.mu.RLock()
	paths := maps.Clone(h.paths)
	h.mu.RUnlock()
	providers := map[string]bool{}
	for _, endpoint := range paths {
		if endpoint.definition.SourceIPs == nil && endpoint.definition.Provider != "custom" {
			providers[endpoint.definition.Provider] = true
		}
	}
	for _, provider := range slices.Sorted(maps.Keys(providers)) {
		previous, found := h.sources[provider]
		if found && now.Before(previous.RefreshAt) {
			continue
		}
		source, err := h.resolve(ctx, h.state, h.server, provider)
		if err == nil && found && previous.Revision != "" && !previous.Any && source.Any {
			err = errors.New("provider policy cannot implicitly become unrestricted")
		}
		if err != nil {
			if ctx.Err() != nil {
				return errors.Join(err, ctx.Err())
			}
			previous.Stale = true
			previous.RefreshAt = now.Add(30 * time.Second)
			h.sources[provider] = previous
			continue
		}
		source.Prefixes = slices.Clone(source.Prefixes)
		h.sources[provider] = source
	}
	current, prefixes, any, err := webhookPolicies(paths, h.sources, h.now())
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.paths = current
	h.mu.Unlock()
	if !any && len(prefixes) == 0 || any == h.ingressAny && slices.Equal(prefixes, h.ingressIPs) {
		return nil
	}
	if install == nil {
		return errors.New("webhook source union installer is unavailable")
	}
	if err := install(ctx, prefixes); err != nil {
		return err
	}
	h.ingressIPs, h.ingressAny = slices.Clone(prefixes), any
	return nil
}

// PolicyStatus describes the actual source policy selected for an endpoint.
func (h *Webhooks) PolicyStatus(name string) string {
	now := h.now()
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, endpoint := range h.paths {
		if endpoint.name != name {
			continue
		}
		if endpoint.unavailable || !endpoint.validUntil.IsZero() && !now.Before(endpoint.validUntil) {
			return "unavailable"
		}
		value := "all sources"
		if !endpoint.any {
			value = strconv.Itoa(len(endpoint.prefixes)) + " IP ranges"
		}
		if endpoint.stale {
			value += " (cached)"
		}
		return value
	}
	return "unavailable"
}

func (h *Webhooks) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	authority, err := naming.CanonicalizeAuthority(request.Host)
	if err != nil || authority != h.hostname {
		diagnostic.WriteHTTP(response, request, diagnostic.RequestMisdirected, "")
		return
	}
	// authorize the exact escaped path before reading or retaining any body bytes.
	h.mu.RLock()
	endpoint, found := h.paths[request.URL.EscapedPath()]
	h.mu.RUnlock()
	if !found || request.URL.RawPath != "" || request.URL.Path != request.URL.EscapedPath() {
		diagnostic.WriteHTTP(response, request, diagnostic.IPPolicyDenied, "")
		return
	}
	methods := endpoint.definition.Methods
	if len(methods) == 0 {
		methods = []string{http.MethodPost}
	}
	if !slices.Contains(methods, request.Method) {
		diagnostic.WriteHTTP(response, request, diagnostic.IPPolicyDenied, "")
		return
	}
	if endpoint.unavailable || !endpoint.validUntil.IsZero() && !h.now().Before(endpoint.validUntil) {
		diagnostic.WriteHTTP(response, request, diagnostic.WebhookUnavailable, "")
		return
	}
	source, err := netip.ParseAddrPort(request.RemoteAddr)
	if err != nil {
		diagnostic.WriteHTTP(response, request, diagnostic.IPPolicyDenied, "")
		return
	}
	allowed := endpoint.any
	for _, prefix := range endpoint.prefixes {
		allowed = allowed || prefix.Contains(source.Addr().Unmap())
	}
	if !allowed {
		diagnostic.WriteHTTP(response, request, diagnostic.IPPolicyDenied, "")
		return
	}
	var receivers []clientstate.TunnelInfo
	if endpoint.definition.DeliveryMode() == "selected" {
		owner, ownerErr := h.state.ExclusiveWebhookReceiver(request.Context(), h.server, h.group, endpoint.name, endpoint.digest)
		err = ownerErr
		if err == nil {
			receivers = []clientstate.TunnelInfo{owner}
		}
	} else {
		receivers, err = h.state.WebhookReceivers(request.Context(), h.server, h.group, endpoint.name, endpoint.digest)
	}
	if err != nil {
		if errors.Is(err, clientstate.ErrWebhookPolicyConflict) {
			h.failure(endpoint.name, "local worktrees", "endpoint policies conflict")
		} else {
			h.failure(endpoint.name, "local worktrees", "local state unavailable or selected receiver unready")
		}
		diagnostic.WriteHTTP(response, request, diagnostic.WebhookUnavailable, "")
		return
	}
	if len(receivers) == 0 || len(receivers) > maxWebhookReceivers {
		h.failure(endpoint.name, "local worktrees", "no matching ready receivers")
		diagnostic.WriteHTTP(response, request, diagnostic.WebhookUnavailable, "")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxWebhookBody))
	if err != nil {
		diagnostic.WriteHTTP(response, request, diagnostic.RequestRejected, "")
		return
	}
	if endpoint.definition.DeliveryMode() == "selected" {
		current, currentErr := h.state.WebhookReceiverCurrent(request.Context(), receivers[0])
		if currentErr != nil || !current {
			if currentErr != nil {
				h.failure(endpoint.name, receivers[0].ID, "local state unavailable")
			}
			diagnostic.WriteHTTP(response, request, diagnostic.WebhookUnavailable, "")
			return
		}
		result, err := deliverWebhook(request, receivers[0], body, true)
		if result.status != 0 && h.OnReceiverResponse != nil {
			h.OnReceiverResponse("selected")
		}
		if err != nil && result.status == 0 {
			h.failure(endpoint.name, receivers[0].ID, "local service unavailable")
			diagnostic.WriteHTTP(response, request, diagnostic.WebhookDeliveryFailed, "")
			return
		}
		if err != nil && result.body == nil {
			diagnostic.WriteHTTP(response, request, diagnostic.WebhookDeliveryFailed, "")
			return
		}
		writeWebhookResponse(response, result)
		return
	}
	results := make([]webhookResponse, len(receivers))
	failures := make([]error, len(receivers))
	var wg sync.WaitGroup
	for index, receiver := range receivers {
		wg.Go(func() {
			current, currentErr := h.state.WebhookReceiverCurrent(request.Context(), receiver)
			if currentErr != nil || !current {
				failures[index] = currentErr
				reason := "local state unavailable"
				if currentErr == nil {
					failures[index] = errors.New("receiver stopped")
					reason = "tunnel stopped"
				}
				h.failure(endpoint.name, receiver.ID, reason)
				return
			}
			results[index], failures[index] = deliverWebhook(request, receiver, body, returnsWebhookResponse(request.Method))
			if results[index].status != 0 && h.OnReceiverResponse != nil {
				h.OnReceiverResponse("fanout")
			}
			if failures[index] != nil {
				reason := "local service unavailable"
				if results[index].status != 0 {
					reason = fmt.Sprintf("HTTP %d", results[index].status)
				}
				h.failure(endpoint.name, receiver.ID, reason)
			}
		})
	}
	wg.Wait()
	for _, err := range failures {
		if err != nil {
			diagnostic.WriteHTTP(response, request, diagnostic.WebhookDeliveryFailed, "")
			return
		}
	}
	if returnsWebhookResponse(request.Method) {
		for _, result := range results[1:] {
			if !reflect.DeepEqual(result, results[0]) {
				diagnostic.WriteHTTP(response, request, diagnostic.WebhookDeliveryFailed, "")
				return
			}
		}
		writeWebhookResponse(response, results[0])
		return
	}
	response.WriteHeader(http.StatusOK)
}

func returnsWebhookResponse(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func (h *Webhooks) failure(endpoint, receiver, reason string) {
	if h.report != nil {
		h.report(endpoint, receiver, reason)
	}
}

type webhookResponse struct {
	status                       int
	contentType, contentEncoding string
	body                         []byte
}

func writeWebhookResponse(response http.ResponseWriter, result webhookResponse) {
	if result.contentType != "" {
		response.Header().Set("Content-Type", result.contentType)
	}
	if result.contentEncoding != "" {
		response.Header().Set("Content-Encoding", result.contentEncoding)
	}
	response.WriteHeader(result.status)
	_, _ = response.Write(result.body)
}

func deliverWebhook(incoming *http.Request, receiver clientstate.TunnelInfo, body []byte, includeResponse bool) (webhookResponse, error) {
	canonicalTarget, err := targetsyntax.NormalizeTarget(receiver.Target)
	if err != nil {
		return webhookResponse{}, err
	}
	parsed, err := url.Parse(canonicalTarget)
	if err != nil {
		return webhookResponse{}, err
	}
	target := parsed.Host
	ctx, cancel := context.WithTimeout(incoming.Context(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, incoming.Method, canonicalTarget+incoming.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return webhookResponse{}, err
	}
	request.GetBody = nil // a failed delivery must not be replayed by the transport.
	request.Host, request.Header = incoming.Host, incoming.Header.Clone()
	for _, value := range request.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			request.Header.Del(strings.TrimSpace(token))
		}
	}
	for key := range request.Header {
		lower := strings.ToLower(key)
		if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-tnl-") {
			request.Header.Del(key)
		}
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override", "X-Method-Override"} {
		request.Header.Del(key)
	}
	source, _, _ := net.SplitHostPort(incoming.RemoteAddr)
	request.Header.Set("X-Forwarded-For", source)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", incoming.Host)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != target {
			return nil, errors.New("unexpected webhook target")
		}
		return dialer.DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	upstream, err := transport.RoundTrip(request)
	if err != nil {
		return webhookResponse{}, err
	}
	defer upstream.Body.Close()
	result := webhookResponse{status: upstream.StatusCode}
	if !includeResponse && (upstream.StatusCode < 200 || upstream.StatusCode >= 300) {
		return result, errors.New("receiver did not acknowledge webhook")
	}
	if !includeResponse {
		_, _ = io.Copy(io.Discard, io.LimitReader(upstream.Body, 64<<10))
		return result, nil
	}
	result.body, err = io.ReadAll(io.LimitReader(upstream.Body, (64<<10)+1))
	if err != nil || len(result.body) > 64<<10 {
		return webhookResponse{}, errors.New("receiver response exceeds limit")
	}
	result.contentType, result.contentEncoding = upstream.Header.Get("Content-Type"), upstream.Header.Get("Content-Encoding")
	if upstream.StatusCode < 200 || upstream.StatusCode >= 300 {
		return result, errors.New("receiver did not acknowledge webhook")
	}
	return result, nil
}
