package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type publishEventType string

const (
	publishEventStarting  publishEventType = "starting"
	publishEventReady     publishEventType = "ready"
	publishEventWarning   publishEventType = "warning"
	publishEventCurrentIP publishEventType = "current_ip"
	publishEventError     publishEventType = "error"
	publishEventStopped   publishEventType = "stopped"
)

type publishOutputMode string

const (
	publishOutputHuman  publishOutputMode = "human"
	publishOutputNDJSON publishOutputMode = "ndjson"
)

type publishEvent struct {
	SchemaVersion    int              `json:"schema_version"`
	Type             publishEventType `json:"type"`
	Cursor           uint64           `json:"cursor"`
	TunnelID         string           `json:"tunnel_id"`
	Target           string           `json:"target,omitempty"`
	URL              string           `json:"url,omitempty"`
	PublishRunNumber uint64           `json:"publish_run_number,omitempty"`
	IP               string           `json:"ip,omitempty"`
	Message          string           `json:"message,omitempty"`
	Code             string           `json:"code,omitempty"`
	HelpURL          string           `json:"help_url,omitempty"`
	Retryable        *bool            `json:"retryable,omitempty"`
	RetryAt          *time.Time       `json:"retry_at,omitempty"`
	Reason           string           `json:"reason,omitempty"`
	Transport        string           `json:"transport,omitempty"`
}

type publishOutput struct {
	mode                  publishOutputMode
	stdout                io.Writer
	stderr                io.Writer
	mu                    sync.Mutex
	cursor                uint64
	tunnelID              string
	printed               bool
	opened                bool
	provision             uint64
	stalled               uint64
	readyPublishRunNumber uint64
	fallbackPublicURL     uint64
	blockPublicURL        uint64
	blocked               uint64
	command               string
	target                string
	current               string
	providers             []providerCount
	allowedPrefixCount    int
	framework             string
	openURL               func(string) error
}

type providerCount struct {
	name  string
	count int
}

type reportedError struct{ err error }

func (e *reportedError) Error() string { return e.err.Error() }
func (e *reportedError) Unwrap() error { return e.err }

func (o *publishOutput) provisioning(hostname string, publishRunNumber uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if publishRunNumber <= o.provision {
		return nil
	}
	o.provision = publishRunNumber
	if o.mode != publishOutputHuman {
		return nil
	}
	return writeHumanTransition(
		o.stderr, o.command, "provisioning", hostname,
		"certificate and publisher connections", o.target, "waiting for public URL readiness",
	)
}

func (o *publishOutput) provisioningStalled(publishRunNumber uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if publishRunNumber != o.provision || publishRunNumber <= o.stalled || publishRunNumber <= o.readyPublishRunNumber {
		return nil
	}
	o.stalled = publishRunNumber
	if o.mode == publishOutputHuman {
		return diagnostic.WriteWarning(o.stderr, o.command, diagnostic.ProvisioningStalled)
	}
	retryable := true
	return o.emitLocked(publishEvent{
		Type: publishEventWarning, Message: diagnostic.Summary(diagnostic.ProvisioningStalled),
		Code: string(diagnostic.ProvisioningStalled), HelpURL: diagnostic.HelpURL(diagnostic.ProvisioningStalled),
		Retryable: &retryable, PublishRunNumber: publishRunNumber,
	})
}

func (o *publishOutput) targetUnavailable() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.mode == publishOutputHuman {
		return diagnostic.WriteWarning(o.stderr, o.command, diagnostic.TargetUnavailable)
	}
	retryable := false
	return o.emitLocked(publishEvent{
		Type: publishEventWarning, Message: diagnostic.Summary(diagnostic.TargetUnavailable),
		Code: string(diagnostic.TargetUnavailable), HelpURL: diagnostic.HelpURL(diagnostic.TargetUnavailable),
		Retryable: &retryable,
	})
}

func (o *publishOutput) transportFallback(publishRunNumber uint64, transport string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if publishRunNumber <= o.fallbackPublicURL {
		return nil
	}
	o.fallbackPublicURL = publishRunNumber
	if o.mode == publishOutputHuman {
		return writeHumanFrame(o.stderr, o.command, "transport fallback", "tunnel continues over TLS/TCP",
			clioutput.Fields(
				clioutput.Field{Label: "transport", Value: "TLS/TCP"},
			),
		)
	}
	retryable := false
	return o.emitLocked(publishEvent{
		Type: publishEventWarning, Message: "QUIC did not establish before TLS/TCP; continuing over TLS/TCP.",
		Retryable: &retryable, PublishRunNumber: publishRunNumber, Transport: transport,
	})
}

// blockedVisitors presents aggregate policy denials without exposing visitor IPs.
func (o *publishOutput) blockedVisitors(publishRunNumber, total uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if publishRunNumber != o.blockPublicURL {
		o.blockPublicURL, o.blocked = publishRunNumber, 0
	}
	if total <= o.blocked {
		return nil
	}
	increase := total - o.blocked
	o.blocked = total
	if o.mode != publishOutputHuman {
		return nil
	}
	return diagnostic.WritePolicyDenial(o.stderr, o.command, increase, total)
}

func newPublishOutput(mode publishOutputMode, command string, stdout, stderr io.Writer, openURL func(string) error) (*publishOutput, error) {
	if mode != publishOutputHuman && mode != publishOutputNDJSON {
		return nil, errors.New("output must be human or ndjson")
	}
	return &publishOutput{mode: mode, command: command, stdout: stdout, stderr: stderr, openURL: openURL}, nil
}

func (o *publishOutput) starting(tunnelID, target string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tunnelID = tunnelID
	o.target = target
	if o.mode == publishOutputHuman {
		return nil
	}
	return o.emitLocked(publishEvent{Type: publishEventStarting, Target: target})
}

func (o *publishOutput) ready(url string, publishRunNumber uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.readyPublishRunNumber = max(o.readyPublishRunNumber, publishRunNumber)
	if o.mode == publishOutputHuman {
		if !o.printed {
			o.printed = true
			footer := "ctrl+c to stop"
			var openErr error
			if o.openURL != nil && !o.opened {
				o.opened = true
				openErr = o.openPublicURL(url)
				if openErr == nil {
					footer = "opened in browser; ctrl+c to stop"
				}
			}
			var fields []clioutput.Field
			if o.framework != "" {
				fields = append(fields, clioutput.Field{Label: "framework", Value: o.framework})
			}
			if o.current != "" {
				fields = append(fields, clioutput.Field{Label: "automatically allowed IP", Value: o.current})
			}
			for _, provider := range o.providers {
				fields = append(fields, clioutput.Field{
					Label: provider.name + " webhook IPs", Value: countState(provider.count, "prefix", "prefixes"),
				})
			}
			if len(o.providers) != 0 {
				fields = append(fields, clioutput.Field{
					Label: "allowed IP prefixes", Value: fmt.Sprint(o.allowedPrefixCount),
				})
			}
			if o.fallbackPublicURL == publishRunNumber {
				fields = append(fields, clioutput.Field{Label: "transport", Value: "TLS/TCP fallback"})
			}
			blocks := []clioutput.Block{clioutput.Flow(
				clioutput.FlowNode{Label: url},
				clioutput.FlowNode{Label: "tnl"},
				clioutput.FlowNode{Label: o.target},
			)}
			if len(fields) != 0 {
				blocks = append(blocks, clioutput.Fields(fields...))
			}
			if err := writeHumanFrame(o.stderr, o.command, "ready", footer, blocks...); err != nil {
				return err
			}
			if openErr != nil {
				_ = writeHumanFrame(o.stderr, o.command, "browser not opened", "public URL remains ready",
					clioutput.Fields(
						clioutput.Field{Label: "URL", Value: url},
						clioutput.Field{Label: "reason", Value: openErr.Error()},
					),
				)
			}
		}
	} else if err := o.emitLocked(publishEvent{Type: publishEventReady, URL: url, PublishRunNumber: publishRunNumber}); err != nil {
		return err
	}
	if o.mode != publishOutputHuman && o.openURL != nil && !o.opened {
		o.opened = true
		if err := o.openPublicURL(url); err != nil {
			_ = writeHumanFrame(o.stderr, o.command, "browser not opened", "public URL remains ready",
				clioutput.Fields(
					clioutput.Field{Label: "URL", Value: url},
					clioutput.Field{Label: "reason", Value: err.Error()},
				),
			)
		}
	}
	return nil
}

// openPublicURL releases the output lock while DNS and the browser opener run.
func (o *publishOutput) openPublicURL(url string) error {
	o.mu.Unlock()
	err := o.openURL(url)
	o.mu.Lock()
	return err
}

func (o *publishOutput) setIPPolicy(policy resolvedIPPolicy) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.providers = make([]providerCount, 0, len(policy.sources))
	for _, source := range policy.sources {
		o.providers = append(o.providers, providerCount{name: source.Name, count: len(source.Prefixes)})
	}
	o.allowedPrefixCount = len(policy.prefixes)
}

func (o *publishOutput) currentIP(ip string) error {
	if o.mode == publishOutputHuman {
		o.mu.Lock()
		o.current = ip
		o.mu.Unlock()
		return nil
	}
	return o.emit(publishEvent{Type: publishEventCurrentIP, IP: ip})
}

func (o *publishOutput) setFramework(framework string) {
	o.mu.Lock()
	o.framework = framework
	o.mu.Unlock()
}

func (o *publishOutput) logf(format string, arguments ...any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	message := fmt.Sprintf(format, arguments...)
	_ = writeHumanFrame(o.stderr, o.command, "publisher connection disrupted", "reconnecting", clioutput.Text(message))
}

func (o *publishOutput) failed(err error) error {
	if o.mode == publishOutputHuman {
		return nil
	}
	retryable := errors.Is(err, controlclient.ErrUnavailable) || errors.Is(err, controlclient.ErrRateLimited) ||
		errors.Is(err, authorityclient.ErrUnavailable) || errors.Is(err, authorityclient.ErrRateLimited)
	event := publishEvent{Type: publishEventError, Message: boundedOutputError(err), Retryable: &retryable}
	if code, ok := diagnostic.CodeOf(err); ok {
		event.Code = string(code)
		event.HelpURL = diagnostic.HelpURL(code)
	}
	var limited *controlclient.RateLimitError
	if errors.As(err, &limited) && limited.RetryAfter > 0 {
		retryAt := time.Now().Add(limited.RetryAfter).UTC()
		event.RetryAt = &retryAt
	} else {
		var authorityLimited *authorityclient.RateLimitError
		if errors.As(err, &authorityLimited) && authorityLimited.RetryAfter > 0 {
			retryAt := time.Now().Add(authorityLimited.RetryAfter).UTC()
			event.RetryAt = &retryAt
		}
	}
	return o.emit(event)
}

func (o *publishOutput) finish(ctx context.Context, result error) error {
	cause := context.Cause(ctx)
	if result == nil {
		result = cause
	} else if cause != nil && !errors.Is(result, cause) {
		result = errors.Join(result, cause)
	}
	result = classifyCommandError(result)
	if result == nil {
		return nil
	}
	if code, render := terminalResult(result); code == 0 && render == nil {
		return errors.Join(result, o.stopped())
	}
	if o.mode == publishOutputHuman {
		return result
	}
	if writeErr := o.failed(result); writeErr != nil {
		return errors.Join(result, fmt.Errorf("write machine error event: %w", writeErr))
	}
	return &reportedError{err: result}
}

func (o *publishOutput) stopped() error {
	if o.mode == publishOutputHuman {
		return nil
	}
	return o.emit(publishEvent{Type: publishEventStopped, Reason: "canceled"})
}

func (o *publishOutput) emit(event publishEvent) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.emitLocked(event)
}

func (o *publishOutput) emitLocked(event publishEvent) error {
	// keep cursor assignment and encoding in one critical section.
	o.cursor++
	event.SchemaVersion = 1
	event.Cursor = o.cursor
	event.TunnelID = o.tunnelID
	return json.NewEncoder(o.stdout).Encode(event)
}

func boundedOutputError(err error) string {
	message := clioutput.DisplayErrorMessage(err.Error())
	if code, ok := diagnostic.CodeOf(err); ok {
		message = diagnostic.Summary(code)
	}
	if len(message) > 1024 {
		return message[:1024]
	}
	return message
}

// handlePublisherEvent is where the CLI handles publisher status and policy
// totals.
func handlePublisherEvent(ctx context.Context, tunnel *clientstate.Tunnel, output *publishOutput, event publisher.Event) error {
	switch event.Type {
	case publisher.EventPublicURLAssigned:
		return tunnel.SetPublicURL(ctx, event.PublicURLID, event.Hostname)
	case publisher.EventProvisioning:
		if err := tunnel.SetProvisioning(ctx, event.PublishRunNumber); err != nil {
			return err
		}
		return output.provisioning(event.Hostname, event.PublishRunNumber)
	case publisher.EventProvisioningStalled:
		return output.provisioningStalled(event.PublishRunNumber)
	case publisher.EventReady:
		if err := tunnel.SetReady(ctx, event.PublicURL, event.PublishRunNumber); err != nil {
			return err
		}
		return output.ready(event.PublicURL, event.PublishRunNumber)
	case publisher.EventDraining:
		return tunnel.SetDraining(context.WithoutCancel(ctx))
	case publisher.EventTransportFallback:
		return output.transportFallback(event.PublishRunNumber, string(event.Transport))
	case publisher.EventIPPolicyDenials:
		return output.blockedVisitors(event.PublishRunNumber, event.PolicyDenials)
	case publisher.EventTargetUnavailable:
		return output.targetUnavailable()
	}
	return nil
}
