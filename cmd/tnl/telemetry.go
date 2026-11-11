package main

import (
	"context"
	"os"
	"sync"
	"sync/atomic"

	"github.com/alecthomas/kong"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/publisher"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type telemetryPayload = api.Event
type telemetryReporter = clienttelemetry.Reporter
type telemetryTrackedCommand = api.CommandOutcomeCommand
type telemetryCommandAction = api.CommandOutcomeAction
type telemetryFailureStage = api.CommandOutcomeFailureStage
type telemetryServerKind = api.PublicationReadyServerKind
type telemetryFrameworkName = api.PublicationReadyFramework
type telemetryPublishMode = api.PublicationReadyPublishMode
type telemetryWebhookDelivery = api.IntegrationOutcomeDelivery
type telemetryEventName string
type telemetryReporterFactory func(string) telemetryReporter

const (
	telemetryInit                                       = api.CommandOutcomeCommandInit
	telemetryLogin                                      = api.CommandOutcomeCommandLogin
	telemetryPublish                                    = api.CommandOutcomeCommandPublish
	telemetrySetupStage                                 = api.Setup
	telemetryCommandStage                               = api.Command
	telemetryAuthenticationStage                        = api.Authentication
	telemetryLocalServiceStage                          = api.LocalService
	telemetryPublicURLStage                             = api.PublicUrl
	telemetryHosted                                     = api.Hosted
	telemetrySelfHosted                                 = api.SelfHosted
	telemetryVite                telemetryFrameworkName = "vite"
	telemetryNext                telemetryFrameworkName = "next"
	telemetryOther                                      = api.PublicationReadyFrameworkOther
	telemetryPublishApp                                 = api.App
	telemetryPublishDemo                                = api.Demo
	telemetryFanout                                     = api.Fanout
	telemetrySelected                                   = api.Selected
	telemetryOAuthReady          telemetryEventName     = "oauth_callback_url_ready"
	telemetryOAuthRedirected     telemetryEventName     = "oauth_callback_redirected"
	telemetryWebhookReady        telemetryEventName     = "webhook_endpoint_ready"
	telemetryWebhookReached      telemetryEventName     = "webhook_delivery_reached_receiver"
)

type telemetryInvocation struct {
	reporter        telemetryReporter
	integrationOnce [4]atomic.Bool
	modeMu          sync.RWMutex
	mode            telemetryPublishMode
	action          telemetryCommandAction
}

func newTelemetryInvocation(reporter telemetryReporter) *telemetryInvocation {
	return &telemetryInvocation{reporter: reporter}
}

func (i *telemetryInvocation) Report(event api.Event) {
	name, _ := event.Discriminator()
	switch name {
	case "command.outcome":
		command, _ := event.AsCommandEvent()
		if i.action != "" {
			command.Payload.Action = &i.action
		}
		_ = event.FromCommandEvent(command)
	case "tunnel.ready":
		ready, _ := event.AsReadyEvent()
		i.modeMu.RLock()
		if i.mode != "" {
			ready.Payload.PublishMode = i.mode
		}
		i.modeMu.RUnlock()
		_ = event.FromReadyEvent(ready)
	case "integration.outcome":
		integration, _ := event.AsIntegrationEvent()
		index := 0
		if integration.Payload.Kind == "webhook" {
			index = 2
		}
		if integration.Payload.Outcome != api.Ready {
			index++
		}
		if !i.integrationOnce[index].CompareAndSwap(false, true) {
			return
		}
	}
	i.reporter.Report(event)
}

func (i *telemetryInvocation) SetPublishMode(mode telemetryPublishMode) {
	i.modeMu.Lock()
	i.mode = mode
	i.modeMu.Unlock()
}
func (i *telemetryInvocation) Flush() { i.reporter.Flush() }
func (i *telemetryInvocation) BeginScope(role api.TransportReportRole, disabled bool) *clienttelemetry.Scope {
	return i.reporter.BeginScope(role, disabled)
}

func (i *telemetryInvocation) finished(command telemetryTrackedCommand, stage telemetryFailureStage, err error) {
	payload := api.CommandOutcome{Command: command, Outcome: api.Succeeded}
	if err != nil {
		payload.Outcome = api.Failed
		if code, ok := diagnostic.CodeOf(err); ok {
			value := string(code)
			payload.DiagnosticCode = &value
			if stage != telemetrySetupStage {
				switch code {
				case diagnostic.AuthenticationTimeout, diagnostic.AuthenticationRequired:
					stage = telemetryAuthenticationStage
				case diagnostic.TargetUnavailable, diagnostic.TargetInvalid:
					stage = telemetryLocalServiceStage
				case diagnostic.PublicURLInvalid, diagnostic.PublicURLConflict, diagnostic.DNSSetupPending, diagnostic.ProvisioningStalled:
					stage = telemetryPublicURLStage
				}
			}
		}
		if code, _ := terminalResult(err); code == 0 {
			payload.Outcome = api.Canceled
			payload.DiagnosticCode = nil
		} else {
			payload.FailureStage = &stage
		}
	}
	i.Report(clienttelemetry.Command(payload))
}

func newTelemetryReady(_ telemetryTrackedCommand, kind telemetryServerKind, framework telemetryFrameworkName) api.Event {
	payload := api.PublicationReady{ServerKind: kind, PublishMode: api.App}
	if framework != "" {
		payload.Framework = &framework
	}
	return clienttelemetry.Ready(payload)
}

func newTelemetryDemoPing() api.Event { return clienttelemetry.Demo() }

func newIntegrationTelemetry(name telemetryEventName, delivery telemetryWebhookDelivery) api.Event {
	payload := api.IntegrationOutcome{Kind: "oauth", Outcome: api.Ready}
	switch name {
	case telemetryOAuthReady:
	case telemetryOAuthRedirected:
		payload.Outcome = api.Redirected
	case telemetryWebhookReady, telemetryWebhookReached:
		payload.Kind, payload.Delivery = "webhook", &delivery
		if name == telemetryWebhookReached {
			payload.Outcome = api.ReachedReceiver
		}
	default:
		return api.Event{}
	}
	return clienttelemetry.Integration(payload)
}

func selectedTelemetryCommand(parsed *kong.Context) (telemetryTrackedCommand, telemetryCommandAction, bool) {
	var command []string
	for _, element := range parsed.Path {
		if element.Command != nil && element.Command.Type == kong.CommandNode {
			command = append(command, element.Command.Name)
		}
	}
	if len(command) == 0 {
		return "", "", false
	}
	name := telemetryTrackedCommand(command[0])
	if !name.Valid() {
		return "", "", false
	}
	var action telemetryCommandAction
	if len(command) > 1 {
		action = telemetryCommandAction(command[len(command)-1])
		if !action.Valid() {
			action = api.CommandOutcomeActionOther
		}
	}
	return name, action, true
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

func withTelemetryObserver(reporter telemetryReporter, command telemetryTrackedCommand, serverURL string, framework func() string, observe func(publisher.Event) error) func(publisher.Event) error {
	if reporter == nil {
		return observe
	}
	kind := telemetrySelfHosted
	if serverURL == defaultServerURL {
		kind = telemetryHosted
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
				reporter.Report(newTelemetryReady(command, kind, name))
				reporter.Flush()
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

func closeTelemetry(c *clienttelemetry.Collector) {
	ctx, stop := context.WithTimeout(context.Background(), clienttelemetry.RequestTimeout)
	defer stop()
	c.Close(ctx)
}
