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

	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

type localPublisherEndpoint struct {
	Version    int    `json:"version"`
	URL        string `json:"url"`
	Credential string `json:"credential"`
}

func runtimeTCPEndpointPath(key string) string { return key + ".endpoint.json" }

func startRuntimeTCP(key string, handler http.Handler) (*http.Server, <-chan error, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen for local publisher requests: %w", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		listener.Close()
		return nil, nil, err
	}
	credential := base64.RawURLEncoding.EncodeToString(secret)
	server := &http.Server{Handler: authorizeLocalPublisher(handler, credential), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}
	endpoint := localPublisherEndpoint{Version: privateprotocol.Version, URL: "http://" + listener.Addr().String(), Credential: credential}
	if err := writeRuntimeTCPEndpoint(runtimeTCPEndpointPath(key), endpoint); err != nil {
		listener.Close()
		return nil, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	return server, done, nil
}

func authorizeLocalPublisher(handler http.Handler, credential string) http.Handler {
	expected := []byte("Bearer " + credential)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" && r.Method == http.MethodGet {
			handler.ServeHTTP(w, r)
			return
		}
		provided := []byte(r.Header.Get("Authorization"))
		if r.Header.Get("Origin") != "" || len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
			privateprotocol.Write(w, http.StatusUnauthorized, privateprotocol.Problem{Code: "runtime.authentication_required", Message: "local publisher credential is required"})
			return
		}
		handler.ServeHTTP(w, r)
	})
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
	return errors.Join(err, os.Remove(runtimeTCPEndpointPath(key)))
}
