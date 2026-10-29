package main

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/alecthomas/kong"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/publisher"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type telemetryReporter = clienttelemetry.Reporter
type telemetryReporterFactory func(string) telemetryReporter
type telemetryTrackedCommand = api.CommandOutcomeCommand
type telemetryCommandAction = api.CommandOutcomeAction
type telemetryFailureStage = api.CommandOutcomeFailureStage
type telemetryServerKind = api.PublicationReadyServerKind
type telemetryFrameworkName = api.PublicationReadyFramework
type telemetryPublishMode = api.PublicationReadyPublishMode
type telemetryWebhookDelivery = api.IntegrationOutcomeDelivery

const (
	telemetryPublish             = api.CommandOutcomeCommandPublish
	telemetrySetupStage          = api.Setup
	telemetryCommandStage        = api.Command
	telemetryAuthenticationStage = api.Authentication
	telemetryLocalServiceStage   = api.LocalService
	telemetryPublicURLStage      = api.PublicUrl
	telemetryHosted              = api.PublicationReadyServerKind("hosted")
	telemetrySelfHosted          = api.PublicationReadyServerKind("self_hosted")
	telemetryPublishApp          = api.App
	telemetryPublishDemo         = api.Demo
	telemetryVite                = api.PublicationReadyFramework("vite")
	telemetryNext                = api.PublicationReadyFramework("next")
	telemetryOther               = api.PublicationReadyFramework("other")
	telemetryFanout              = api.IntegrationOutcomeDelivery("fanout")
	telemetrySelected            = api.IntegrationOutcomeDelivery("selected")
)

type telemetryInvocation struct {
	reporter        telemetryReporter
	ready           atomic.Bool
	integrationOnce [4]atomic.Bool
	modeMu          sync.RWMutex
	mode            telemetryPublishMode
}

func newTelemetryInvocation(reporter telemetryReporter) *telemetryInvocation {
	return &telemetryInvocation{reporter: reporter}
}

func (i *telemetryInvocation) Report(observation clienttelemetry.Observation) {
	var once *atomic.Bool
	switch observation.Event {
	case clienttelemetry.OAuthReady:
		once = &i.integrationOnce[0]
	case clienttelemetry.OAuthRedirected:
		once = &i.integrationOnce[1]
	case clienttelemetry.WebhookReady:
		once = &i.integrationOnce[2]
	case clienttelemetry.WebhookReached:
		once = &i.integrationOnce[3]
	}
	if once != nil && !once.CompareAndSwap(false, true) {
		return
	}
	if observation.Event == clienttelemetry.PublicationReady {
		i.modeMu.RLock()
		observation.PublishMode = i.mode
		i.modeMu.RUnlock()
		i.ready.Store(true)
	}
	i.reporter.Report(observation)
}

func (i *telemetryInvocation) SetPublishMode(mode telemetryPublishMode) {
	i.modeMu.Lock()
	i.mode = mode
	i.modeMu.Unlock()
}

func (i *telemetryInvocation) flushReady() {
	if reporter, ok := i.reporter.(interface{ Flush() }); ok {
		reporter.Flush()
	}
}

func (i *telemetryInvocation) failed(command telemetryTrackedCommand, action telemetryCommandAction, stage telemetryFailureStage, err error) {
	if code, ok := diagnostic.CodeOf(err); ok && stage != telemetrySetupStage {
		switch code {
		case diagnostic.AuthenticationTimeout, diagnostic.AuthenticationRequired:
			stage = telemetryAuthenticationStage
		case diagnostic.TargetUnavailable, diagnostic.TargetInvalid:
			stage = telemetryLocalServiceStage
		case diagnostic.PublicURLInvalid, diagnostic.PublicURLConflict, diagnostic.DNSSetupPending, diagnostic.ProvisioningStalled:
			stage = telemetryPublicURLStage
		}
	}
	i.Report(clienttelemetry.Observation{Event: clienttelemetry.CommandFailed, Command: command, Action: action, FailureStage: stage})
}

func newTelemetryReady(kind telemetryServerKind, framework telemetryFrameworkName) clienttelemetry.Observation {
	return clienttelemetry.Observation{Event: clienttelemetry.PublicationReady, ServerKind: kind, PublishMode: telemetryPublishApp, Framework: framework}
}

func newTelemetryDemoPing() clienttelemetry.Observation {
	return clienttelemetry.Observation{Event: clienttelemetry.DemoFirstPing}
}

func newIntegrationTelemetry(name string, delivery telemetryWebhookDelivery) clienttelemetry.Observation {
	observation := clienttelemetry.Observation{Delivery: delivery}
	switch name {
	case "oauth_callback_url_ready":
		observation.Event = clienttelemetry.OAuthReady
	case "oauth_callback_redirected":
		observation.Event = clienttelemetry.OAuthRedirected
	case "webhook_endpoint_ready":
		observation.Event = clienttelemetry.WebhookReady
	case "webhook_delivery_reached_receiver":
		observation.Event = clienttelemetry.WebhookReached
	}
	return observation
}

func selectedTelemetryCommand(parsed *kong.Context) (telemetryTrackedCommand, telemetryCommandAction, bool) {
	var command []string
	for _, element := range parsed.Path {
		if element.Command != nil && element.Command.Type == kong.CommandNode {
			command = append(command, element.Command.Name)
		}
	}
	if len(command) == 0 || command[0] == "telemetry" || command[0] == "version" || command[0] == "runtime" {
		return "", "", false
	}
	name := telemetryTrackedCommand(command[0])
	if command[0] == "login" || command[0] == "logout" {
		name = api.CommandOutcomeCommandAuth
	}
	if !name.Valid() {
		name = api.CommandOutcomeCommandOther
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
	serverURL string,
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
				reporter.Report(newTelemetryReady(serverKind, name))
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

// a foreground invocation checks the saved preference with a short budget and
// opens the collector in the background. the collector observes later changes.
func newTelemetryReporter(ctx context.Context, root string) *clienttelemetry.Deferred {
	collector, err := clienttelemetry.NewDeferred(ctx, clienttelemetry.Config{Root: root})
	if err != nil {
		return nil
	}
	return collector
}

func runNativeProcess(ctx context.Context, args []string, stdout, stderr io.Writer, open func(context.Context, string) *clienttelemetry.Deferred) error {
	var collector *clienttelemetry.Deferred
	defer func() {
		if collector != nil {
			flush, cancel := context.WithTimeout(context.Background(), clienttelemetry.RequestTimeout)
			defer cancel()
			collector.Close(flush)
		}
	}()
	return run(context.WithValue(ctx, nativeProcessKey{}, true), args, stdout, stderr, func(root string) telemetryReporter {
		// the command reports its terminal observation after cancellation. this
		// process owns the collector until the bounded final flush joins it.
		collector = open(context.WithoutCancel(ctx), root)
		if collector == nil {
			return nil
		}
		return collector
	})
}

func telemetryCommandOutcome(ctx context.Context, result error) clienttelemetry.EventKind {
	if result == nil && ctx.Err() == nil {
		return clienttelemetry.CommandCompleted
	}
	if errors.Is(result, context.Canceled) || ctx.Err() != nil {
		return clienttelemetry.CommandCanceled
	}
	return clienttelemetry.CommandFailed
}
