package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

type localPublisherEndpoint struct {
	Version    int    `json:"version"`
	URL        string `json:"url"`
	Credential string `json:"credential"`
}

func runtimeTCPEndpointPath(key string) string { return key + ".endpoint.json" }
func runtimeAppEndpointPath(key, service string) string {
	return key + ".app." + service + ".endpoint.json"
}
func runtimeAdHocEndpointPath(key string) string { return key + ".ad-hoc.endpoint.json" }

type localScopeKind string

const (
	localScopeOwner localScopeKind = "owner"
	localScopeApp   localScopeKind = "app"
	localScopeAdHoc localScopeKind = "ad-hoc"
)

type localPublisherScope struct {
	kind    localScopeKind
	service string
}

type localScopeContextKey struct{}

type localPublisherAuthorization struct {
	mu       sync.RWMutex
	key      string
	endpoint localPublisherEndpoint
	handler  http.Handler
	scoped   map[string]localPublisherScope
	apps     map[string]string
	paths    []string
}

func localPublisherScopeFrom(ctx context.Context) localPublisherScope {
	if scope, ok := ctx.Value(localScopeContextKey{}).(localPublisherScope); ok {
		return scope
	}
	return localPublisherScope{kind: localScopeOwner}
}

func publisherCredential() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

func startRuntimeTCP(key string, handler http.Handler, services ...clientruntime.Service) (*http.Server, <-chan error, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen for local publisher requests: %w", err)
	}
	credential, err := publisherCredential()
	if err != nil {
		listener.Close()
		return nil, nil, err
	}
	endpoint := localPublisherEndpoint{Version: privateprotocol.Version, URL: "http://" + listener.Addr().String(), Credential: credential}
	auth := &localPublisherAuthorization{key: key, endpoint: endpoint, handler: handler,
		scoped: map[string]localPublisherScope{}, apps: map[string]string{},
		paths: []string{runtimeAdHocEndpointPath(key)},
	}
	defer func() {
		if err != nil {
			listener.Close()
			for _, path := range auth.paths {
				_ = os.Remove(path)
			}
		}
	}()
	adHocCredential, err := publisherCredential()
	if err != nil {
		return nil, nil, err
	}
	auth.scoped[adHocCredential] = localPublisherScope{kind: localScopeAdHoc}
	if err = writeRuntimeTCPEndpoint(auth.paths[0], localPublisherEndpoint{Version: privateprotocol.Version, URL: endpoint.URL, Credential: adHocCredential}); err != nil {
		return nil, nil, err
	}
	for _, service := range services {
		if service.ServiceProtocol != "" {
			continue
		}
		if err = auth.issueApp(service.Name); err != nil {
			return nil, nil, err
		}
	}
	if err = writeRuntimeTCPEndpoint(runtimeTCPEndpointPath(key), endpoint); err != nil {
		return nil, nil, err
	}
	server := &http.Server{Handler: auth, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	return server, done, nil
}

func (a *localPublisherAuthorization) issueApp(service string) error {
	if !naming.ValidServiceName(service) {
		return failure.Wrap("select app credential", failure.ServiceNotConfigured, errors.New("app service name is invalid"))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	token := a.apps[service]
	if token == "" {
		var err error
		token, err = publisherCredential()
		if err != nil {
			return err
		}
	}
	path := runtimeAppEndpointPath(a.key, service)
	if err := writeRuntimeTCPEndpoint(path, localPublisherEndpoint{Version: privateprotocol.Version, URL: a.endpoint.URL, Credential: token}); err != nil {
		return failure.Wrap("write app credential", failure.ClientStateUnavailable, err)
	}
	if a.apps[service] == "" {
		a.paths = append(a.paths, path)
		a.apps[service] = token
		a.scoped[token] = localPublisherScope{kind: localScopeApp, service: service}
	}
	return nil
}

func (a *localPublisherAuthorization) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/health" && r.Method == http.MethodGet {
		a.handler.ServeHTTP(w, r)
		return
	}
	provided := []byte(r.Header.Get("Authorization"))
	expected := []byte("Bearer " + a.endpoint.Credential)
	scope := localPublisherScope{kind: localScopeOwner}
	authorized := len(provided) == len(expected) && subtle.ConstantTimeCompare(provided, expected) == 1
	if !authorized && len(provided) == len(expected) {
		a.mu.RLock()
		for token, candidate := range a.scoped {
			if subtle.ConstantTimeCompare(provided, []byte("Bearer "+token)) == 1 {
				authorized, scope = true, candidate
				break
			}
		}
		a.mu.RUnlock()
	}
	if !authorized || r.Header.Get("Origin") != "" || scope.kind == localScopeAdHoc &&
		!strings.HasPrefix(r.URL.Path, "/v1/ad-hoc/") && r.URL.Path != "/v1/status" || scope.kind == localScopeApp &&
		r.URL.Path != "/v1/status" && r.URL.Path != "/v1/prepare" && r.URL.Path != "/v1/register" &&
		r.URL.Path != "/v1/renew" && r.URL.Path != "/v1/unregister" {
		privateprotocol.Write(w, http.StatusUnauthorized, privateprotocol.Problem{Code: "runtime.authentication_required", Message: "local publisher credential is required"})
		return
	}
	if scope.kind == localScopeOwner && r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/scopes/app/") {
		if err := a.issueApp(strings.TrimPrefix(r.URL.Path, "/v1/scopes/app/")); err != nil {
			runtimeProblem(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	a.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), localScopeContextKey{}, scope)))
}

func writeRuntimeTCPEndpoint(path string, endpoint localPublisherEndpoint) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".publisher-endpoint-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := json.NewEncoder(file).Encode(endpoint); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func readRuntimeTCPEndpoint(key string) (localPublisherEndpoint, error) {
	return readLocalPublisherDescriptor(runtimeTCPEndpointPath(key))
}

func ensureAppPublisherEndpoint(ctx context.Context, key, service string) error {
	if !runtimeAvailable(ctx, key) {
		return nil
	}
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URL+"/v1/scopes/app/"+service, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
	response, err := client.Do(request)
	if err != nil {
		if !runtimeAvailable(ctx, key) {
			return nil
		}
		return failure.Wrap("issue app credential", failure.ClientStateUnavailable, err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return failure.Wrap("issue app credential", failure.ClientStateUnavailable, fmt.Errorf("local publisher returned HTTP %d", response.StatusCode))
	}
	return nil
}

func readLocalPublisherDescriptor(path string) (localPublisherEndpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return localPublisherEndpoint{}, err
	}
	if len(data) > 4096 {
		return localPublisherEndpoint{}, errors.New("local publisher endpoint descriptor is too large")
	}
	var endpoint localPublisherEndpoint
	if err := json.Unmarshal(data, &endpoint); err != nil {
		return localPublisherEndpoint{}, err
	}
	if endpoint.Version != privateprotocol.Version || endpoint.Credential == "" {
		return localPublisherEndpoint{}, errors.New("local publisher endpoint descriptor is invalid")
	}
	host, ok := strings.CutPrefix(endpoint.URL, "http://")
	if !ok {
		return localPublisherEndpoint{}, errors.New("local publisher endpoint is not a loopback TCP address")
	}
	address, err := net.ResolveTCPAddr("tcp", host)
	if err != nil || !address.IP.IsLoopback() || address.Port <= 0 {
		return localPublisherEndpoint{}, errors.New("local publisher endpoint is not a loopback TCP address")
	}
	return endpoint, nil
}

func stopRuntimeTCP(ctx context.Context, server *http.Server, key string) error {
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := server.Shutdown(closeCtx)
	err = errors.Join(err, os.Remove(runtimeTCPEndpointPath(key)))
	if auth, ok := server.Handler.(*localPublisherAuthorization); ok {
		auth.mu.Lock()
		for _, path := range auth.paths {
			err = errors.Join(err, os.Remove(path))
		}
		auth.mu.Unlock()
	}
	return err
}
