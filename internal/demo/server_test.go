package demo

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDemoPingUsesLocalStateAndStopsWithServer(t *testing.T) {
	var mu sync.Mutex
	var received []State
	demo, err := Start(func(state State) error {
		mu.Lock()
		received = append(received, state)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if closed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := demo.Close(ctx); err != nil {
			t.Fatal(err)
		}
	})
	address := strings.TrimPrefix(demo.Target(), "http://")
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("demo listener = %s: %v", demo.Target(), err)
	}
	client := &http.Client{Timeout: time.Second}
	get := func(path string) *http.Response {
		t.Helper()
		response, err := client.Get(demo.Target() + path)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	page := get("/")
	data, err := io.ReadAll(page.Body)
	page.Body.Close()
	if err != nil || page.StatusCode != http.StatusOK || !strings.Contains(string(data), "fira-code-latin-wght-normal.woff2") ||
		!strings.Contains(string(data), "tnl server") || !strings.Contains(string(data), "round trip") ||
		!strings.Contains(string(data), "generated at") ||
		page.Header.Get("Cache-Control") != "no-store" ||
		strings.Contains(string(data), "fonts.googleapis.com") ||
		strings.Contains(page.Header.Get("Content-Security-Policy"), "fonts.gstatic.com") ||
		!strings.Contains(page.Header.Get("Content-Security-Policy"), "font-src 'self'") {
		t.Fatalf("demo page = %d, %v, %q", page.StatusCode, err, data)
	}
	for _, name := range []string{"fira-code-latin-wght-normal.woff2", "fira-code-symbols2-wght-normal.woff2"} {
		font := get("/fonts/" + name)
		data, err := io.ReadAll(font.Body)
		font.Body.Close()
		if err != nil || font.StatusCode != http.StatusOK || font.Header.Get("Content-Type") != "font/woff2" ||
			len(data) < 4 || string(data[:4]) != "wOF2" {
			t.Fatalf("demo font %s = %d, %v", name, font.StatusCode, err)
		}
	}

	response, err := client.Post(demo.Target()+"/ping", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("ping before ready = %d", response.StatusCode)
	}
	demo.SetPublicURL("https://actual.generated.tnl.dev")
	for count := uint64(1); count <= 2; count++ {
		response, err := client.Post(demo.Target()+"/ping", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		var pong State
		err = json.NewDecoder(response.Body).Decode(&pong)
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || pong.PublicURL != "https://actual.generated.tnl.dev" ||
			pong.Stamp != demo.Stamp() || len(pong.Stamp) != 8 || pong.RequestCount != count {
			t.Fatalf("pong %d = %+v, status %d, error %v", count, pong, response.StatusCode, err)
		}
		if generated, err := time.Parse(time.RFC3339Nano, pong.GeneratedAt); err != nil ||
			generated.Before(time.Now().Add(-time.Minute)) || generated.After(time.Now().Add(time.Minute)) {
			t.Fatalf("pong generated at = %q, error = %v", pong.GeneratedAt, err)
		}
	}
	mu.Lock()
	if len(received) != 2 || received[0].RequestCount != 1 || received[1].RequestCount != 2 || received[1].Stamp != demo.Stamp() {
		t.Fatalf("terminal callbacks = %+v", received)
	}
	mu.Unlock()
	stateResponse := get("/state")
	var state State
	if err := json.NewDecoder(stateResponse.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, stateResponse.Body)
	stateResponse.Body.Close()
	if state.PublicURL != "https://actual.generated.tnl.dev" || state.RequestCount != 2 || state.GeneratedAt == "" {
		t.Fatalf("state = %+v", state)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := demo.Close(ctx); err != nil {
		t.Fatal(err)
	}
	closed = true
	if response, err := client.Get(demo.Target() + "/"); err == nil {
		response.Body.Close()
		t.Fatal("demo still accepts connections after stopping")
	}
}
