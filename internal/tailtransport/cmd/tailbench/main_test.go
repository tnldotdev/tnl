package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/types/key"
)

func TestAuthorize(t *testing.T) {
	agent := &agent{token: "secret"}
	handler := agent.authorize(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, test := range []struct {
		header string
		want   int
	}{
		{"", http.StatusUnauthorized},
		{"secret", http.StatusUnauthorized},
		{"Basic secret", http.StatusUnauthorized},
		{"Bearer wrong", http.StatusUnauthorized},
		{"Bearer secret", http.StatusNoContent},
	} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Authorization", test.header)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Errorf("Authorization %q returned %d; want %d", test.header, response.Code, test.want)
		}
	}
}

func TestCreateRunRejectsInvalidKey(t *testing.T) {
	agent := new(agent)
	request := httptest.NewRequest(http.MethodPost, "/v1/run", strings.NewReader(`{"client_public_keys":["invalid"]}`))
	response := httptest.NewRecorder()

	agent.createRun(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want %d", response.Code, http.StatusBadRequest)
	}
	if agent.state != runIdle {
		t.Fatalf("state = %d; want idle", agent.state)
	}
}

func TestCreateRunRejectsShutdown(t *testing.T) {
	agent := new(agent)
	if result := agent.shutdown(context.Background()); result != (closeResult{}) {
		t.Fatalf("shutdown result = %+v; want empty", result)
	}
	publicKey := key.NewNode().Public().String()
	request := httptest.NewRequest(http.MethodPost, "/v1/run", strings.NewReader(`{"client_public_keys":["`+publicKey+`"]}`))
	response := httptest.NewRecorder()

	agent.createRun(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestCloseRunUsesMatchingCompletion(t *testing.T) {
	firstErr := errors.New("first close")
	laterErr := errors.New("later close")
	canceled := make(chan struct{})
	first := &runCompletion{done: make(chan struct{})}
	agent := &agent{
		state:      runCreating,
		cancel:     func() { close(canceled) },
		completion: first,
	}
	result := make(chan closeResult, 1)
	go func() {
		result <- agent.closeRun(context.Background())
	}()
	<-canceled

	agent.mu.Lock()
	first.result.closeErr = firstErr
	close(first.done)
	agent.state = runClosing
	agent.completion = &runCompletion{
		done:   make(chan struct{}),
		result: closeResult{closeErr: laterErr},
	}
	agent.mu.Unlock()

	if got := (<-result).closeErr; !errors.Is(got, firstErr) {
		t.Fatalf("close error = %v; want %v", got, firstErr)
	}
}
