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

func startRuntimeTCP(key string, handler http.Handler, appServices ...string) (*http.Server, <-chan error, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen for local publisher requests: %w", err)
	}
	credential, err := runtimeCredential()
	if err != nil {
		listener.Close()
		return nil, nil, err
	}
	endpoint := localPublisherEndpoint{Version: privateprotocol.Version, URL: "http://" + listener.Addr().String(), Credential: credential}
	if err := writeRuntimeTCPEndpoint(runtimeTCPEndpointPath(key), endpoint); err != nil {
		listener.Close()
		return nil, nil, err
	}
	appTokens := make(map[string]string, len(appServices))
	for _, service := range appServices {
		if !naming.ValidServiceName(service) {
			listener.Close()
			removeRuntimeTCPEndpoints(key, appServices)
			return nil, nil, errors.New("invalid local publisher app service")
		}
		token, err := runtimeCredential()
		if err == nil {
			err = writeRuntimeTCPEndpoint(runtimeAppTCPEndpointPath(key, service), localPublisherEndpoint{Version: privateprotocol.Version, URL: endpoint.URL, Credential: token})
		}
		if err != nil {
			listener.Close()
			removeRuntimeTCPEndpoints(key, appServices)
			return nil, nil, err
		}
		appTokens[token] = service
	}
	server := &http.Server{Handler: authorizeLocalPublisher(handler, credential, listener.Addr().String(), appTokens), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}
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

func authorizeLocalPublisher(handler http.Handler, credential, address string, apps map[string]string) http.Handler {
	expected := []byte("Bearer " + credential)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != address || r.Header.Get("Origin") != "" {
			localUnauthorized(w)
			return
		}
		if r.URL.Path == "/v1/health" && r.Method == http.MethodGet {
			handler.ServeHTTP(w, r)
			return
		}
		provided := []byte(r.Header.Get("Authorization"))
		if len(provided) == len(expected) && subtle.ConstantTimeCompare(provided, expected) == 1 {
			if r.URL.Path != "/v1/status" && r.URL.Path != "/v1/events" && r.URL.Path != "/v1/publications" && !strings.HasPrefix(r.URL.Path, "/v1/publications/") {
				localUnauthorized(w)
				return
			}
			handler.ServeHTTP(w, r)
			return
		}
		for token, service := range apps {
			app := []byte("Bearer " + token)
			if len(provided) == len(app) && subtle.ConstantTimeCompare(provided, app) == 1 {
				if r.URL.Path != "/v1/prepare" && !strings.HasPrefix(r.URL.Path, "/v1/registrations/") {
					break
				}
				handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), localPublisherScopeKey{}, service)))
				return
			}
		}
		localUnauthorized(w)
	})
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
	return errors.Join(err, removeRuntimeTCPEndpoints(key, apps))
}
