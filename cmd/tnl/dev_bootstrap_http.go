package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"reflect"
	"strings"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/localproxy"
)

const maxDevRequestBytes = 16 << 10

func (b *devBootstrap) handle(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || (request.URL.Path != "/v1/configure" && request.URL.Path != "/v1/target") {
		http.NotFound(response, request)
		return
	}
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		http.Error(response, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if request.URL.Path == "/v1/configure" {
		b.handleConfiguration(response, request)
		return
	}
	b.handleTarget(response, request)
}

func (b *devBootstrap) handleConfiguration(response http.ResponseWriter, request *http.Request) {
	var configuration devConfigurationRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxDevRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&configuration); err != nil {
		http.Error(response, "invalid development configuration", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(response, "invalid development configuration", http.StatusBadRequest)
		return
	}
	if configuration.Protocol != 1 || !validFrameworkName(configuration.Framework) {
		http.Error(response, "invalid development configuration", http.StatusBadRequest)
		return
	}
	b.mu.Lock()
	first := b.configuration == nil
	if !first && !reflect.DeepEqual(*b.configuration, configuration) {
		b.mu.Unlock()
		http.Error(response, "different development settings are already registered", http.StatusConflict)
		return
	}
	if first {
		configured := configuration
		b.configuration = &configured
	}
	b.mu.Unlock()
	if first {
		select {
		case b.configurations <- configuration:
		case <-b.closing:
			http.Error(response, "development session is closing", http.StatusServiceUnavailable)
			return
		}
	}

	select {
	case <-b.resolved:
		b.mu.Lock()
		assignment := b.assignment
		configurationErr := b.configurationErr
		b.mu.Unlock()
		if configurationErr != nil {
			http.Error(response, presentFailure(configurationErr).message, http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(assignment); err != nil {
			return
		}
	case <-b.closing:
		http.Error(response, "development session closed before configuration completed", http.StatusServiceUnavailable)
	case <-request.Context().Done():
		return
	}
}

func (b *devBootstrap) handleTarget(response http.ResponseWriter, request *http.Request) {
	var targetRequest devTargetRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxDevRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&targetRequest); err != nil {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	if targetRequest.Protocol != 1 || !validFrameworkName(targetRequest.Framework) {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	target, err := localproxy.NormalizeTarget(targetRequest.Target)
	if err != nil {
		http.Error(response, "invalid target registration", http.StatusBadRequest)
		return
	}
	targetRequest.Target = target

	b.mu.Lock()
	if b.configuration == nil {
		b.mu.Unlock()
		http.Error(response, "development target was registered before configuration", http.StatusConflict)
		return
	}
	if b.configuration.Framework != targetRequest.Framework {
		b.mu.Unlock()
		http.Error(response, "target framework does not match development configuration", http.StatusConflict)
		return
	}
	if b.targetErr != nil {
		b.mu.Unlock()
		http.Error(response, "development target registration already failed", http.StatusConflict)
		return
	}
	first := b.target == nil
	if !first && !reflect.DeepEqual(*b.target, targetRequest) {
		b.mu.Unlock()
		http.Error(response, "a different development target is already registered", http.StatusConflict)
		return
	}
	if first && b.forcedPort != "" {
		_, registeredPort, splitErr := net.SplitHostPort(strings.TrimPrefix(target, "http://"))
		if splitErr != nil || registeredPort != b.forcedPort {
			mismatch := diagnostic.Wrap(
				diagnostic.TargetMismatch,
				fmt.Errorf("development server registered port %s instead of port %s required by tnl dev", registeredPort, b.forcedPort),
			)
			b.targetErr = mismatch
			b.mu.Unlock()
			select {
			case b.targets <- devTargetResult{err: mismatch}:
			case <-b.closing:
				http.Error(response, "development session is closing", http.StatusServiceUnavailable)
				return
			}
			http.Error(response, "registered target does not use the port forced by tnl dev --port", http.StatusConflict)
			return
		}
	}
	if first {
		registered := targetRequest
		b.target = &registered
	}
	b.mu.Unlock()
	if first {
		select {
		case b.targets <- devTargetResult{target: targetRequest}:
		case <-b.closing:
			http.Error(response, "development session is closing", http.StatusServiceUnavailable)
			return
		}
	}
	response.WriteHeader(http.StatusNoContent)
}

func validFrameworkName(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			return false
		}
	}
	return true
}
