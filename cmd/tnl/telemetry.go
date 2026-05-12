package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/publisher"
)

const (
	telemetryReceiverURL    = "https://tnl.dev/api/telemetry"
	telemetryRequestTimeout = 500 * time.Millisecond
)

type telemetryPayload struct {
	InstallationID string `json:"installation_id"`
	Event          string `json:"event"`
	Command        string `json:"command"`
	ServerKind     string `json:"server_kind,omitempty"`
	Version        string `json:"version"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	CI             bool   `json:"ci"`
}

type telemetryReporter interface {
	Report(telemetryPayload)
}

type telemetryReporterFactory func(string) telemetryReporter

type asyncTelemetryReporter struct {
	root   string
	client *http.Client

	idOnce sync.Once
	id     string
	wait   sync.WaitGroup
}

func newTelemetryReporter(root string) *asyncTelemetryReporter {
	return &asyncTelemetryReporter{
		root: root,
		client: &http.Client{
			Timeout: telemetryRequestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (r *asyncTelemetryReporter) Report(payload telemetryPayload) {
	r.wait.Add(1)
	go func() {
		defer r.wait.Done()
		ctx, cancel := context.WithTimeout(context.Background(), telemetryRequestTimeout)
		defer cancel()

		r.idOnce.Do(func() {
			state, err := clientstate.Open(ctx, r.root)
			if err != nil {
				return
			}
			defer state.Close()
			r.id, _ = state.InstallationID(ctx)
		})
		if r.id == "" {
			return
		}
		payload.InstallationID = r.id
		body, err := json.Marshal(payload)
		if err != nil {
			return
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, telemetryReceiverURL, bytes.NewReader(body))
		if err != nil {
			return
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "")
		response, err := r.client.Do(request)
		if err == nil {
			_ = response.Body.Close()
		}
	}()
}

func (r *asyncTelemetryReporter) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		r.wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func newTelemetryPayload(event, command, serverKind string) telemetryPayload {
	return telemetryPayload{
		Event: event, Command: command, ServerKind: serverKind,
		Version: buildinfo.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, CI: os.Getenv("CI") != "",
	}
}

func canonicalTelemetryCommand(parsed *kong.Context) string {
	var command []string
	for _, element := range parsed.Path {
		if element.Command != nil && element.Command.Type == kong.CommandNode {
			command = append(command, element.Command.Name)
		}
	}
	return strings.Join(command, " ")
}

func telemetryStateRoot(parsed *kong.Context) (string, error) {
	stateDir := ""
	for _, flag := range parsed.Flags() {
		if flag.Name != "state-dir" || !hasEnvironment(flag.Envs, "TNL_STATE_DIR") {
			continue
		}
		if value, ok := parsed.FlagValue(flag).(string); ok {
			stateDir = value
		}
	}
	return clientStateRoot(stateDir)
}

func hasEnvironment(environments []string, name string) bool {
	for _, environment := range environments {
		if environment == name {
			return true
		}
	}
	return false
}

func optionalTelemetryReporter(reporters []telemetryReporter) telemetryReporter {
	if len(reporters) == 0 {
		return nil
	}
	return reporters[0]
}

func withTelemetryObserver(
	reporter telemetryReporter,
	command, serverURL string,
	observe func(publisher.Event) error,
) func(publisher.Event) error {
	if reporter == nil {
		return observe
	}
	serverKind := "self_hosted"
	if serverURL == defaultServerURL {
		serverKind = "hosted"
	}
	var ready sync.Once
	return func(event publisher.Event) error {
		if observe != nil {
			if err := observe(event); err != nil {
				return err
			}
		}
		if event.Type == publisher.EventReady {
			ready.Do(func() {
				reporter.Report(newTelemetryPayload("route_started", command, serverKind))
			})
		}
		return nil
	}
}
