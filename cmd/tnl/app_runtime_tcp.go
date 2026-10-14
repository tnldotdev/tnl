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

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

type localPublisherEndpoint struct {
	Version    int    `json:"version"`
	URL        string `json:"url"`
	Credential string `json:"credential"`
}

func runtimeTCPEndpointPath(key string) string { return key + ".endpoint.json" }
func runtimeAppTCPEndpointPath(key, service string) string {
	return key + ".app." + service + ".endpoint.json"
}

type localPublisherAuthorization struct {
	mu       sync.RWMutex
	key      string
	owner    localPublisherEndpoint
	appURL   string
	appPaths map[string]string
	handler  http.Handler
	apps     map[string]string
}

func startRuntimeTCP(key string, handler http.Handler, appServices ...string) (*http.Server, <-chan error, error) {
	return startRuntimeTCPWithOptions(key, handler, "127.0.0.1:0", "", nil, appServices...)
}

func startRuntimeTCPCompose(key string, handler http.Handler, listen, service string, paths map[string]string, appServices ...string) (*http.Server, <-chan error, error) {
	if !naming.ValidServiceName(service) || len(paths) == 0 {
		return nil, nil, errors.New("select a Compose publisher and separate app endpoint volumes")
	}
	return startRuntimeTCPWithOptions(key, handler, listen, service, paths, appServices...)
}

func startRuntimeTCPWithOptions(key string, handler http.Handler, listen, service string, paths map[string]string, appServices ...string) (*http.Server, <-chan error, error) {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for local publisher requests: %w", err)
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()
	credential, err := runtimeCredential()
	if err != nil {
		listener.Close()
		return nil, nil, err
	}
	endpoint := localPublisherEndpoint{Version: privateprotocol.Version, URL: "http://127.0.0.1:" + fmt.Sprint(listener.Addr().(*net.TCPAddr).Port), Credential: credential}
	appURL := endpoint.URL
	if service != "" {
		appURL = "http://" + net.JoinHostPort(service, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	}
	if err := writeRuntimeTCPEndpoint(runtimeTCPEndpointPath(key), endpoint); err != nil {
		listener.Close()
		return nil, nil, err
	}
	auth := &localPublisherAuthorization{key: key, owner: endpoint, appURL: appURL, appPaths: paths, handler: handler, apps: make(map[string]string, len(appServices))}
	for _, service := range appServices {
		if err := auth.issueApp(service); err != nil {
			listener.Close()
			_ = auth.removeEndpoints()
			return nil, nil, err
		}
	}
	server := &http.Server{Handler: auth, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	return server, done, nil
}

type localPublisherScopeKey struct{}

func localPublisherService(ctx context.Context) string {
	service, _ := ctx.Value(localPublisherScopeKey{}).(string)
	return service
}

func runtimeCredential() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

func (a *localPublisherAuthorization) issueApp(service string) error {
	if !naming.ValidServiceName(service) {
		return errors.New("invalid local publisher app service")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	token := a.apps[service]
	if token == "" {
		var err error
		token, err = runtimeCredential()
		if err != nil {
			return err
		}
	}
	path := runtimeAppTCPEndpointPath(a.key, service)
	if a.appPaths != nil {
		path = a.appPaths[service]
	}
	if path == "" {
		return errors.New("configured app has no private endpoint volume")
	}
	if err := writeRuntimeTCPEndpoint(path, localPublisherEndpoint{
		Version: privateprotocol.Version, URL: a.appURL, Credential: token,
	}); err != nil {
		return err
	}
	a.apps[service] = token
	return nil
}

func (a *localPublisherAuthorization) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != "" || r.Host != strings.TrimPrefix(a.owner.URL, "http://") && r.Host != strings.TrimPrefix(a.appURL, "http://") {
		localUnauthorized(w)
		return
	}
	if r.URL.Path == "/v1/health" && r.Method == http.MethodGet {
		a.handler.ServeHTTP(w, r)
		return
	}
	provided := []byte(r.Header.Get("Authorization"))
	expected := []byte("Bearer " + a.owner.Credential)
	if len(provided) == len(expected) && subtle.ConstantTimeCompare(provided, expected) == 1 {
		if r.Host != strings.TrimPrefix(a.owner.URL, "http://") {
			localUnauthorized(w)
			return
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/scopes/app/") {
			if err := a.issueApp(strings.TrimPrefix(r.URL.Path, "/v1/scopes/app/")); err != nil {
				runtimeProblem(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/v1/status" || r.URL.Path == "/v1/events" || r.URL.Path == "/v1/observe" || strings.HasPrefix(r.URL.Path, "/v1/ad-hoc/") {
			a.handler.ServeHTTP(w, r)
			return
		}
		localUnauthorized(w)
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for service, token := range a.apps {
		app := []byte("Bearer " + token)
		if len(provided) == len(app) && subtle.ConstantTimeCompare(provided, app) == 1 {
			if r.Host != strings.TrimPrefix(a.appURL, "http://") {
				break
			}
			if r.URL.Path == "/v1/prepare" || r.URL.Path == "/v1/status" || strings.HasPrefix(r.URL.Path, "/v1/registrations/") {
				a.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), localPublisherScopeKey{}, service)))
				return
			}
			break
		}
	}
	localUnauthorized(w)
}

func localUnauthorized(w http.ResponseWriter) {
	privateprotocol.Write(w, http.StatusUnauthorized, privateprotocol.Problem{Code: "runtime.authentication_required", Message: "local publisher credential is required"})
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
	data, err := os.ReadFile(runtimeTCPEndpointPath(key))
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
	ip, port, err := net.SplitHostPort(host)
	if err != nil || ip != "127.0.0.1" || port == "" || strings.ContainsAny(port, "/?#") {
		return localPublisherEndpoint{}, errors.New("local publisher endpoint is not a loopback TCP address")
	}
	address, err := net.ResolveTCPAddr("tcp", host)
	if err != nil || address.Port <= 0 {
		return localPublisherEndpoint{}, errors.New("local publisher endpoint is not a loopback TCP address")
	}
	return endpoint, nil
}

func removeRuntimeTCPEndpoints(key string, apps []string) error {
	err := os.Remove(runtimeTCPEndpointPath(key))
	for _, service := range apps {
		if naming.ValidServiceName(service) {
			err = errors.Join(err, os.Remove(runtimeAppTCPEndpointPath(key, service)))
		}
	}
	return err
}

func stopRuntimeTCP(ctx context.Context, server *http.Server, key string, apps ...string) error {
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := server.Shutdown(closeCtx)
	if auth, ok := server.Handler.(*localPublisherAuthorization); ok {
		return errors.Join(err, auth.removeEndpoints())
	}
	return errors.Join(err, removeRuntimeTCPEndpoints(key, apps))
}

func (a *localPublisherAuthorization) removeEndpoints() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	err := os.Remove(runtimeTCPEndpointPath(a.key))
	for service := range a.apps {
		path := runtimeAppTCPEndpointPath(a.key, service)
		if a.appPaths != nil {
			path = a.appPaths[service]
		}
		err = errors.Join(err, os.Remove(path))
	}
	return err
}
