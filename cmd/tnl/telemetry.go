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
	"sync/atomic"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
)

const (
	telemetryReceiverURL    = "https://tnl.dev/api/telemetry"
	telemetryRequestTimeout = 500 * time.Millisecond
)

type telemetryEventName string

const (
	telemetryCommandStarted    telemetryEventName = "command_started"
	telemetryCommandCompleted  telemetryEventName = "command_completed"
	telemetryCommandFailed     telemetryEventName = "command_failed"
	telemetryPublishRunStarted telemetryEventName = "publish_run_started"
	telemetryDemoPingReceived  telemetryEventName = "demo_ping_received"
)

type telemetryTrackedCommand string
type telemetryCommandAction string

const (
	telemetryInit    telemetryTrackedCommand = "init"
	telemetryLogin   telemetryTrackedCommand = "login"
	telemetryDev     telemetryTrackedCommand = "dev"
	telemetryPublish telemetryTrackedCommand = "publish"
)

type telemetryFailureStage string

const (
	telemetrySetupStage          telemetryFailureStage = "setup"
	telemetryCommandStage        telemetryFailureStage = "command"
	telemetryAuthenticationStage telemetryFailureStage = "authentication"
	telemetryLocalServiceStage   telemetryFailureStage = "local_service"
	telemetryPublicURLStage      telemetryFailureStage = "public_url"
)

type telemetryServerKind string

const (
	telemetryHosted     telemetryServerKind = "hosted"
	telemetrySelfHosted telemetryServerKind = "self_hosted"
)

type telemetryFrameworkName string

const (
	telemetryVite  telemetryFrameworkName = "vite"
	telemetryNext  telemetryFrameworkName = "next"
	telemetryOther telemetryFrameworkName = "other"
)

type telemetryPublishMode string

const (
	telemetryPublishApp  telemetryPublishMode = "app"
	telemetryPublishDemo telemetryPublishMode = "demo"
)

type telemetryPayload struct {
	InstallationID string                  `json:"installation_id"`
	InvocationID   string                  `json:"invocation_id"`
	Event          telemetryEventName      `json:"event"`
	Command        telemetryTrackedCommand `json:"command"`
	Action         telemetryCommandAction  `json:"action,omitempty"`
	FailureStage   telemetryFailureStage   `json:"failure_stage,omitempty"`
	DiagnosticCode diagnostic.Code         `json:"diagnostic_code,omitempty"`
	ServerKind     telemetryServerKind     `json:"server_kind,omitempty"`
	PublishMode    telemetryPublishMode    `json:"publish_mode,omitempty"`
	Framework      telemetryFrameworkName  `json:"framework,omitempty"`
	Version        string                  `json:"version"`
	OS             string                  `json:"os"`
	Arch           string                  `json:"arch"`
	CI             bool                    `json:"ci"`
}

type telemetryReporter interface {
	Report(telemetryPayload)
}

type telemetryReporterFactory func(string) telemetryReporter

type telemetryEventID string

type telemetryWireEvent struct {
	EventID      telemetryEventID `json:"event_id"`
	InvocationID string           `json:"invocation_id"`
	OccurredAt   time.Time        `json:"occurred_at"`
	Name         string           `json:"name"`
	EventVersion int              `json:"event_version"`
	Payload      any              `json:"payload"`
}

func (payload telemetryPayload) wireEvent(id telemetryEventID) telemetryWireEvent {
	event := telemetryWireEvent{EventID: id, InvocationID: payload.InvocationID,
		OccurredAt: time.Now().UTC(), EventVersion: 1}
	switch payload.Event {
	case telemetryCommandStarted, telemetryCommandCompleted, telemetryCommandFailed:
		event.Name = "command." + strings.TrimPrefix(string(payload.Event), "command_")
		command := struct {
			Command        telemetryTrackedCommand `json:"command"`
			Action         telemetryCommandAction  `json:"action,omitempty"`
			FailureStage   telemetryFailureStage   `json:"failure_stage,omitempty"`
			DiagnosticCode diagnostic.Code         `json:"diagnostic_code,omitempty"`
		}{payload.Command, payload.Action, payload.FailureStage, payload.DiagnosticCode}
		event.Payload = command
	case telemetryPublishRunStarted:
		event.Name = "tunnel.ready"
		event.Payload = struct {
			Source      telemetryTrackedCommand `json:"source"`
			ServerKind  telemetryServerKind     `json:"server_kind"`
			Framework   telemetryFrameworkName  `json:"framework,omitempty"`
			PublishMode telemetryPublishMode    `json:"publish_mode,omitempty"`
		}{payload.Command, payload.ServerKind, payload.Framework, payload.PublishMode}
	case telemetryDemoPingReceived:
		event.Name = "demo.first_ping"
		event.Payload = struct {
			PublishMode telemetryPublishMode `json:"publish_mode"`
		}{telemetryPublishDemo}
	}
	return event
}

type telemetryInvocation struct {
	reporter telemetryReporter
	id       string
	ready    atomic.Bool
	modeMu   sync.RWMutex
	mode     telemetryPublishMode
	action   telemetryCommandAction
}

func newTelemetryInvocation(reporter telemetryReporter) (*telemetryInvocation, error) {
	id, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		return nil, err
	}
	return &telemetryInvocation{reporter: reporter, id: id}, nil
}

func (i *telemetryInvocation) Report(payload telemetryPayload) {
	payload.InvocationID = i.id
	payload.Action = i.action
	if payload.Command == telemetryPublish {
		i.modeMu.RLock()
		payload.PublishMode = i.mode
		i.modeMu.RUnlock()
	}
	if payload.Event == telemetryPublishRunStarted {
		i.ready.Store(true)
	}
	i.reporter.Report(payload)
}

func (i *telemetryInvocation) SetPublishMode(mode telemetryPublishMode) {
	i.modeMu.Lock()
	i.mode = mode
	i.modeMu.Unlock()
}

func (i *telemetryInvocation) flushReady() {
	if reporter, ok := i.reporter.(interface{ flushReady() }); ok {
		reporter.flushReady()
	}
}

func (i *telemetryInvocation) failed(command telemetryTrackedCommand, stage telemetryFailureStage, err error) {
	if i.ready.Load() {
		return
	}
	payload := newTelemetryBase(command)
	payload.Event = telemetryCommandFailed
	if code, ok := diagnostic.CodeOf(err); ok {
		payload.DiagnosticCode = code
		if stage != telemetrySetupStage {
			switch code {
			case diagnostic.AuthenticationTimeout, diagnostic.AuthenticationRequired:
				stage = telemetryAuthenticationStage
			case diagnostic.TargetUnavailable, diagnostic.TargetInvalid, diagnostic.FrameworkRegistrationTimeout,
				diagnostic.TargetMismatch, diagnostic.DevCommandRecursion:
				stage = telemetryLocalServiceStage
			case diagnostic.PublicURLInvalid, diagnostic.PublicURLConflict, diagnostic.DNSSetupPending,
				diagnostic.ProvisioningStalled:
				stage = telemetryPublicURLStage
			}
		}
	}
	payload.FailureStage = stage
	i.Report(payload)
}

type asyncTelemetryReporter struct {
	root   string
	client *http.Client

	idMu    sync.Mutex
	id      string
	wait    sync.WaitGroup
	flushMu sync.Mutex
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
	id, err := opaqueid.New(opaqueid.TelemetryEventPrefix)
	if err != nil {
		return
	}
	event := payload.wireEvent(telemetryEventID(id))
	if event.Name == "" {
		return
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), telemetryRequestTimeout)
	state, err := clientstate.Open(ctx, r.root)
	if err == nil {
		err = state.QueueTelemetryEvent(ctx, id, encoded)
		_ = state.Close()
	}
	cancel()
	if err != nil {
		return
	}
}

func (r *asyncTelemetryReporter) flushReady() {
	r.wait.Add(1)
	go func() {
		defer r.wait.Done()
		ctx, cancel := context.WithTimeout(context.Background(), telemetryRequestTimeout)
		defer cancel()
		r.flush(ctx)
	}()
}

func (r *asyncTelemetryReporter) flush(ctx context.Context) {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	state, err := clientstate.Open(ctx, r.root)
	if err != nil {
		return
	}
	defer state.Close()
	if enabled, err := state.TelemetryEnabled(ctx); err != nil || !enabled {
		return
	}
	_ = state.PruneTelemetryOutbox(ctx)
	pending, err := state.PendingTelemetryEvents(ctx, 25)
	if err != nil || len(pending) == 0 {
		return
	}
	installationID, err := state.InstallationID(ctx)
	if err != nil {
		return
	}
	events := make([]json.RawMessage, 0, len(pending))
	for _, item := range pending {
		events = append(events, item.JSON)
	}
	body, err := json.Marshal(struct {
		SchemaVersion  int    `json:"schema_version"`
		InstallationID string `json:"installation_id"`
		Client         struct {
			Version string `json:"version"`
			OS      string `json:"os"`
			Arch    string `json:"arch"`
			CI      bool   `json:"ci"`
		} `json:"client"`
		Events []json.RawMessage `json:"events"`
	}{1, installationID, struct {
		Version string `json:"version"`
		OS      string `json:"os"`
		Arch    string `json:"arch"`
		CI      bool   `json:"ci"`
	}{buildinfo.Version, runtime.GOOS, runtime.GOARCH, os.Getenv("CI") != ""}, events})
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
		if response.StatusCode == http.StatusNoContent || response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != http.StatusTooManyRequests {
			_ = state.DeleteTelemetryEvents(ctx, pending)
		}
	}
}

func (r *asyncTelemetryReporter) installationID(ctx context.Context) (string, error) {
	r.idMu.Lock()
	defer r.idMu.Unlock()
	if r.id != "" {
		return r.id, nil
	}
	state, err := clientstate.Open(ctx, r.root)
	if err != nil {
		return "", err
	}
	defer state.Close()
	r.id, err = state.InstallationID(ctx)
	return r.id, err
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

func newTelemetryBase(command telemetryTrackedCommand) telemetryPayload {
	return telemetryPayload{
		Command: command,
		Version: buildinfo.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, CI: os.Getenv("CI") != "",
	}
}

func newTelemetryStarted(command telemetryTrackedCommand) telemetryPayload {
	payload := newTelemetryBase(command)
	payload.Event = telemetryCommandStarted
	return payload
}

func newTelemetryCompleted(command telemetryTrackedCommand) telemetryPayload {
	payload := newTelemetryBase(command)
	payload.Event = telemetryCommandCompleted
	return payload
}

func newTelemetryReady(command telemetryTrackedCommand, kind telemetryServerKind, framework telemetryFrameworkName) telemetryPayload {
	payload := newTelemetryBase(command)
	payload.Event = telemetryPublishRunStarted
	payload.ServerKind = kind
	payload.Framework = framework
	return payload
}

func newTelemetryDemoPing() telemetryPayload {
	payload := newTelemetryBase(telemetryPublish)
	payload.Event = telemetryDemoPingReceived
	payload.PublishMode = telemetryPublishDemo
	return payload
}

func selectedTelemetryCommand(parsed *kong.Context) (telemetryTrackedCommand, telemetryCommandAction, bool) {
	var command []string
	for _, element := range parsed.Path {
		if element.Command != nil && element.Command.Type == kong.CommandNode {
			command = append(command, element.Command.Name)
		}
	}
	if len(command) == 0 || command[0] == "telemetry" || command[0] == "version" {
		return "", "", false
	}
	if len(command) == 1 {
		switch command[0] {
		case "init", "login", "logout", "dev", "publish", "status":
			return telemetryTrackedCommand(command[0]), "", true
		default:
			return "", "", false
		}
	}
	return telemetryTrackedCommand(strings.Join(command[:len(command)-1], " ")), telemetryCommandAction(command[len(command)-1]), true
}

func commandStateRoot(parsed *kong.Context) (string, error) {
	stateDir := os.Getenv("TNL_STATE_DIR")
	if stateDir != "" {
		stateDir = kong.ExpandPath(stateDir)
	}
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
	if invocation, ok := reporters[0].(*telemetryInvocation); ok && invocation == nil {
		return nil
	}
	return reporters[0]
}

func withTelemetryObserver(
	reporter telemetryReporter,
	command telemetryTrackedCommand, serverURL string,
	framework func() string,
	observe func(publisher.Event) error,
) func(publisher.Event) error {
	if reporter == nil {
		return observe
	}
	serverKind := telemetrySelfHosted
	if serverURL == defaultServerURL {
		serverKind = telemetryHosted
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
				var name telemetryFrameworkName
				if framework != nil {
					name = telemetryFramework(framework())
				}
				reporter.Report(newTelemetryReady(command, serverKind, name))
				if invocation, ok := reporter.(*telemetryInvocation); ok {
					invocation.flushReady()
				}
			})
		}
		return nil
	}
}

func telemetryFramework(framework string) telemetryFrameworkName {
	switch framework {
	case "":
		return ""
	case "vite":
		return telemetryVite
	case "next":
		return telemetryNext
	default:
		return telemetryOther
	}
}
