package integrationurls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/webhookips"
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
}

type Webhooks struct {
	state                   *clientstate.Database
	server, group, hostname string
	paths                   map[string]webhookEndpoint
	// report contains only endpoint/tunnel identifiers and fixed failure reasons.
	report func(string, string, string)
	// OnReceiverResponse runs after a selected local service returns HTTP headers.
	OnReceiverResponse func(string)
}

func NewWebhooks(ctx context.Context, state *clientstate.Database, server, group, hostname string, definitions map[string]config.Webhook, report func(string, string, string)) (*Webhooks, []string, error) {
	return newWebhooks(ctx, state, server, group, hostname, definitions, report, webhookips.Resolve)
}

func newWebhooks(ctx context.Context, state *clientstate.Database, server, group, hostname string, definitions map[string]config.Webhook, report func(string, string, string), resolve func(context.Context, webhookips.Cache, string) (webhookips.Source, error)) (*Webhooks, []string, error) {
	services := config.Services{}
	providers := map[string]bool{}
	for _, definition := range definitions {
		if definition.Service != "" {
			services[definition.Service] = config.Service{}
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
	sources := map[string]webhookips.Source{}
	for _, name := range names {
		source, err := resolve(ctx, state, name)
		if err != nil {
			continue
		}
		sources[name] = source
	}
	handler := &Webhooks{state: state, server: server, group: group, hostname: hostname, paths: map[string]webhookEndpoint{}, report: report}
	union := map[string]bool{}
	allowAll := false
	for name, definition := range definitions {
		_, digest, err := DefinitionBytes(definition)
		if err != nil {
			return nil, nil, err
		}
		endpoint := webhookEndpoint{name: name, definition: definition, digest: digest}
		prefixes := slices.Clone(definition.SourceIPs)
		if definition.SourceIPs == nil {
			source, found := sources[definition.Provider]
			if !found {
				endpoint.unavailable = true
				if report != nil {
					report(name, "provider catalog", "source policy unavailable")
				}
			} else {
				endpoint.any = source.Any
				endpoint.stale = source.Stale
				prefixes = source.Prefixes
			}
		}
		allowAll = allowAll || endpoint.any
		for _, value := range prefixes {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, addressErr := netip.ParseAddr(value)
				if addressErr != nil {
					return nil, nil, fmt.Errorf("invalid webhook IP prefix: %w", err)
				}
				prefix = netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen())
			}
			endpoint.prefixes = append(endpoint.prefixes, prefix)
			union[prefix.String()] = true
		}
		handler.paths[definition.Path] = endpoint
	}
	prefixes := []string{}
	if !allowAll {
		for prefix := range union {
			prefixes = append(prefixes, prefix)
		}
		slices.Sort(prefixes)
	}
	return handler, prefixes, nil
}

// PolicyStatus describes the actual source policy selected for an endpoint.
func (h *Webhooks) PolicyStatus(name string) string {
	for _, endpoint := range h.paths {
		if endpoint.name != name {
			continue
		}
		if endpoint.unavailable {
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
		diagnostic.WriteHTTP(response, request, diagnostic.RequestMisdirected)
		return
	}
	// authorize the exact escaped path before reading or retaining any body bytes.
	endpoint, found := h.paths[request.URL.EscapedPath()]
	if !found || request.URL.RawPath != "" || request.URL.Path != request.URL.EscapedPath() {
		diagnostic.WriteHTTP(response, request, diagnostic.IPPolicyDenied)
		return
	}
	methods := endpoint.definition.Methods
	if len(methods) == 0 {
		methods = []string{http.MethodPost}
	}
	if !slices.Contains(methods, request.Method) {
		diagnostic.WriteHTTP(response, request, diagnostic.IPPolicyDenied)
		return
	}
	if endpoint.unavailable {
		diagnostic.WriteHTTP(response, request, diagnostic.WebhookUnavailable)
		return
	}
	source, err := netip.ParseAddrPort(request.RemoteAddr)
	if err != nil {
		diagnostic.WriteHTTP(response, request, diagnostic.IPPolicyDenied)
		return
	}
	allowed := endpoint.any
	for _, prefix := range endpoint.prefixes {
		allowed = allowed || prefix.Contains(source.Addr().Unmap())
	}
	if !allowed {
		diagnostic.WriteHTTP(response, request, diagnostic.IPPolicyDenied)
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
		diagnostic.WriteHTTP(response, request, diagnostic.WebhookUnavailable)
		return
	}
	if len(receivers) == 0 || len(receivers) > maxWebhookReceivers {
		h.failure(endpoint.name, "local worktrees", "no matching ready receivers")
		diagnostic.WriteHTTP(response, request, diagnostic.WebhookUnavailable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxWebhookBody))
	if err != nil {
		diagnostic.WriteHTTP(response, request, diagnostic.RequestRejected)
		return
	}
	if endpoint.definition.DeliveryMode() == "selected" {
		current, currentErr := h.state.WebhookReceiverCurrent(request.Context(), receivers[0])
		if currentErr != nil || !current {
			if currentErr != nil {
				h.failure(endpoint.name, receivers[0].ID, "local state unavailable")
			}
			diagnostic.WriteHTTP(response, request, diagnostic.WebhookUnavailable)
			return
		}
		result, err := deliverWebhook(request, receivers[0], body, true)
		if result.status != 0 && h.OnReceiverResponse != nil {
			h.OnReceiverResponse("selected")
		}
		if err != nil && result.status == 0 {
			h.failure(endpoint.name, receivers[0].ID, "local service unavailable")
			diagnostic.WriteHTTP(response, request, diagnostic.WebhookDeliveryFailed)
			return
		}
		if err != nil && result.body == nil {
			diagnostic.WriteHTTP(response, request, diagnostic.WebhookDeliveryFailed)
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
			diagnostic.WriteHTTP(response, request, diagnostic.WebhookDeliveryFailed)
			return
		}
	}
	if returnsWebhookResponse(request.Method) {
		for _, result := range results[1:] {
			if !reflect.DeepEqual(result, results[0]) {
				diagnostic.WriteHTTP(response, request, diagnostic.WebhookDeliveryFailed)
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
	canonicalTarget, err := localproxy.NormalizeTarget(receiver.Target)
	if err != nil {
		return webhookResponse{}, err
	}
	target := strings.TrimPrefix(canonicalTarget, "http://")
	ctx, cancel := context.WithTimeout(incoming.Context(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, incoming.Method, "http://"+target+incoming.URL.RequestURI(), bytes.NewReader(body))
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
