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
	telemetryOAuthReady        telemetryEventName = "oauth_callback_url_ready"
	telemetryOAuthRedirected   telemetryEventName = "oauth_callback_redirected"
	telemetryWebhookReady      telemetryEventName = "webhook_endpoint_ready"
	telemetryWebhookReached    telemetryEventName = "webhook_delivery_reached_receiver"
)

type telemetryTrackedCommand string
type telemetryCommandAction string

const (
	telemetryInit     telemetryTrackedCommand = "init"
	telemetryLogin    telemetryTrackedCommand = "login"
	telemetryPublish  telemetryTrackedCommand = "publish"
	telemetryRequests telemetryTrackedCommand = "requests"
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
type telemetryWebhookDelivery string

const (
	telemetryFanout   telemetryWebhookDelivery = "fanout"
	telemetrySelected telemetryWebhookDelivery = "selected"
)

const (
	telemetryPublishApp  telemetryPublishMode = "app"
	telemetryPublishDemo telemetryPublishMode = "demo"
)

type telemetryPayload struct {
	InstallationID string                   `json:"installation_id"`
	InvocationID   string                   `json:"invocation_id"`
	Event          telemetryEventName       `json:"event"`
	Command        telemetryTrackedCommand  `json:"command"`
	Action         telemetryCommandAction   `json:"action,omitempty"`
	FailureStage   telemetryFailureStage    `json:"failure_stage,omitempty"`
	DiagnosticCode diagnostic.Code          `json:"diagnostic_code,omitempty"`
	ServerKind     telemetryServerKind      `json:"server_kind,omitempty"`
	PublishMode    telemetryPublishMode     `json:"publish_mode,omitempty"`
	Framework      telemetryFrameworkName   `json:"framework,omitempty"`
	Delivery       telemetryWebhookDelivery `json:"delivery,omitempty"`
	Version        string                   `json:"version"`
	OS             string                   `json:"os"`
	Arch           string                   `json:"arch"`
	CI             bool                     `json:"ci"`
}

type telemetryReporter interface {
	Report(telemetryPayload)
}

type telemetryReporterFactory func(string) telemetryReporter

type telemetryInvocation struct {
	reporter        telemetryReporter
	id              string
	ready           atomic.Bool
	integrationOnce [4]atomic.Bool
	modeMu          sync.RWMutex
	mode            telemetryPublishMode
	action          telemetryCommandAction
}

func newTelemetryInvocation(reporter telemetryReporter) (*telemetryInvocation, error) {
	id, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		return nil, err
	}
	return &telemetryInvocation{reporter: reporter, id: id}, nil
}

func (i *telemetryInvocation) Report(payload telemetryPayload) {
	var once *atomic.Bool
	switch payload.Event {
	case telemetryOAuthReady:
		once = &i.integrationOnce[0]
	case telemetryOAuthRedirected:
		once = &i.integrationOnce[1]
	case telemetryWebhookReady:
		once = &i.integrationOnce[2]
	case telemetryWebhookReached:
		once = &i.integrationOnce[3]
	}
	if once != nil && !once.CompareAndSwap(false, true) {
		return
	}
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
			case diagnostic.TargetUnavailable, diagnostic.TargetInvalid:
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
	if event == nil {
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
	body, err := json.Marshal(telemetryBatch{SchemaVersion: 1, InstallationID: installationID,
		Client: telemetryClientMetadata{Version: buildinfo.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, CI: os.Getenv("CI") != ""},
		Events: events})
	if err != nil {
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, telemetryReceiverURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "tnl")
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

func newIntegrationTelemetry(name telemetryEventName, delivery telemetryWebhookDelivery) telemetryPayload {
	return telemetryPayload{Event: name, Delivery: delivery}
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
		case "init", "login", "logout", "publish", "status":
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
