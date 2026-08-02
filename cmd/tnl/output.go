package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type publishEvent struct {
	SchemaVersion int        `json:"schema_version"`
	Type          string     `json:"type"`
	Cursor        uint64     `json:"cursor"`
	TunnelID      string     `json:"tunnel_id"`
	Target        string     `json:"target,omitempty"`
	URL           string     `json:"url,omitempty"`
	RouteVersion  uint64     `json:"route_version,omitempty"`
	IP            string     `json:"ip,omitempty"`
	Message       string     `json:"message,omitempty"`
	Code          string     `json:"code,omitempty"`
	HelpURL       string     `json:"help_url,omitempty"`
	Retryable     *bool      `json:"retryable,omitempty"`
	RetryAt       *time.Time `json:"retry_at,omitempty"`
	Reason        string     `json:"reason,omitempty"`
	Transport     string     `json:"transport,omitempty"`
}

type publishOutput struct {
	mode              string
	stdout            io.Writer
	stderr            io.Writer
	mu                sync.Mutex
	cursor            uint64
	tunnelID          string
	printed           bool
	opened            bool
	provision         uint64
	stalled           uint64
	readyRouteVersion uint64
	fallbackRoute     uint64
	blockRoute        uint64
	blocked           uint64
	command           string
	target            string
	current           string
	framework         string
	openURL           func(string) error
}

func (o *publishOutput) provisioning(hostname string, routeVersion uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if routeVersion <= o.provision {
		return nil
	}
	o.provision = routeVersion
	if o.mode != "human" {
		return nil
	}
	return writeHumanTransition(
		o.stderr, o.command, "provisioning", hostname,
		"certificate and publisher connections", o.target, "waiting for route readiness",
		clioutput.Field{Label: "route version", Value: fmt.Sprint(routeVersion)},
	)
}

func (o *publishOutput) provisioningStalled(routeVersion uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if routeVersion != o.provision || routeVersion <= o.stalled || routeVersion <= o.readyRouteVersion {
		return nil
	}
	o.stalled = routeVersion
	if o.mode == "human" {
		return diagnostic.WriteWarning(o.stderr, o.command, diagnostic.ProvisioningStalled)
	}
	retryable := true
	return o.emitLocked(publishEvent{
		Type: "warning", Message: diagnostic.Summary(diagnostic.ProvisioningStalled),
		Code: string(diagnostic.ProvisioningStalled), HelpURL: diagnostic.HelpURL(diagnostic.ProvisioningStalled),
		Retryable: &retryable, RouteVersion: routeVersion,
	})
}

func (o *publishOutput) transportFallback(routeVersion uint64, transport string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if routeVersion <= o.fallbackRoute {
		return nil
	}
	o.fallbackRoute = routeVersion
	if o.mode == "human" {
		return writeHumanFrame(o.stderr, o.command, "transport fallback", "tunnel continues over TLS/TCP",
			clioutput.Fields(
				clioutput.Field{Label: "route version", Value: fmt.Sprint(routeVersion)},
				clioutput.Field{Label: "transport", Value: "TLS/TCP"},
			),
		)
	}
	retryable := false
	return o.emitLocked(publishEvent{
		Type: "warning", Message: "QUIC did not establish before TLS/TCP; continuing over TLS/TCP.",
		Retryable: &retryable, RouteVersion: routeVersion, Transport: transport,
	})
}

// blockedVisitors presents aggregate policy denials without exposing visitor IPs.
func (o *publishOutput) blockedVisitors(routeVersion, total uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if routeVersion != o.blockRoute {
		o.blockRoute, o.blocked = routeVersion, 0
	}
	if total <= o.blocked {
		return nil
	}
	increase := total - o.blocked
	o.blocked = total
	if o.mode != "human" {
		return nil
	}
	return writeHumanFrame(o.stderr, o.command, "visitors blocked", "IP policy remains active",
		clioutput.Fields(
			clioutput.Field{Label: "newly blocked", Value: fmt.Sprint(increase)},
			clioutput.Field{Label: "total blocked", Value: fmt.Sprint(total)},
		),
	)
}

func newPublishOutput(mode, command string, stdout, stderr io.Writer, openURL func(string) error) (*publishOutput, error) {
	if mode != "human" && mode != "ndjson" {
		return nil, errors.New("output must be human or ndjson")
	}
	return &publishOutput{mode: mode, command: command, stdout: stdout, stderr: stderr, openURL: openURL}, nil
}

func (o *publishOutput) starting(tunnelID, target string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tunnelID = tunnelID
	o.target = target
	if o.mode == "human" {
		return nil
	}
	return o.emitLocked(publishEvent{Type: "starting", Target: target})
}

func (o *publishOutput) ready(url string, routeVersion uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.readyRouteVersion = max(o.readyRouteVersion, routeVersion)
	if o.mode == "human" {
		if !o.printed {
			o.printed = true
			footer := "ctrl+c to stop"
			var openErr error
			if o.openURL != nil && !o.opened {
				o.opened = true
				openErr = o.openURL(url)
				if openErr == nil {
					footer = "opened in browser; ctrl+c to stop"
				}
			}
			fields := []clioutput.Field{{Label: "route version", Value: fmt.Sprint(routeVersion)}}
			if o.framework != "" {
				fields = append(fields, clioutput.Field{Label: "framework", Value: o.framework})
			}
			if o.current != "" {
				fields = append(fields, clioutput.Field{Label: "IP policy", Value: o.current})
			}
			if o.fallbackRoute == routeVersion {
				fields = append(fields, clioutput.Field{Label: "transport", Value: "TLS/TCP fallback"})
			}
			if err := writeHumanFrame(o.stderr, o.command, "ready", footer,
				clioutput.Flow(
					clioutput.FlowNode{Label: url},
					clioutput.FlowNode{Label: "publisher"},
					clioutput.FlowNode{Label: o.target},
				),
				clioutput.Fields(fields...),
			); err != nil {
				return err
			}
			if openErr != nil {
				_ = writeHumanFrame(o.stderr, o.command, "browser not opened", "route remains ready",
					clioutput.Fields(
						clioutput.Field{Label: "public", Value: url},
						clioutput.Field{Label: "reason", Value: openErr.Error()},
					),
				)
			}
		}
	} else if err := o.emitLocked(publishEvent{Type: "ready", URL: url, RouteVersion: routeVersion}); err != nil {
		return err
	}
	if o.mode != "human" && o.openURL != nil && !o.opened {
		o.opened = true
		if err := o.openURL(url); err != nil {
			_, _ = fmt.Fprintf(o.stderr, "tnl: could not open %s: %v\n", url, err)
		}
	}
	return nil
}

func (o *publishOutput) currentIP(ip string) error {
	if o.mode == "human" {
		o.mu.Lock()
		o.current = ip
		o.mu.Unlock()
		return nil
	}
	return o.emit(publishEvent{Type: "current_ip", IP: ip})
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
	if o.mode == "human" {
		_ = writeHumanFrame(o.stderr, o.command, "publisher connection disrupted", "reconnecting", clioutput.Text(message))
		return
	}
	_, _ = fmt.Fprintf(o.stderr, "tnl: %s\n", message)
}

func (o *publishOutput) failed(err error) error {
	if o.mode == "human" {
		return nil
	}
	retryable := errors.Is(err, controlclient.ErrUnavailable) || errors.Is(err, controlclient.ErrRateLimited)
	event := publishEvent{Type: "error", Message: boundedOutputError(err), Retryable: &retryable}
	if code, ok := diagnostic.CodeOf(err); ok {
		event.Code = string(code)
		event.HelpURL = diagnostic.HelpURL(code)
	}
	var limited *controlclient.RateLimitError
	if errors.As(err, &limited) && limited.RetryAfter > 0 {
		retryAt := time.Now().Add(limited.RetryAfter).UTC()
		event.RetryAt = &retryAt
	}
	return o.emit(event)
}

func (o *publishOutput) stopped() error {
	if o.mode == "human" {
		return nil
	}
	return o.emit(publishEvent{Type: "stopped", Reason: "canceled"})
}

func (o *publishOutput) emit(event publishEvent) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.emitLocked(event)
}

func (o *publishOutput) emitLocked(event publishEvent) error {
	// Keep cursor assignment and encoding in one critical section.
	o.cursor++
	event.SchemaVersion = 1
	event.Cursor = o.cursor
	event.TunnelID = o.tunnelID
	return json.NewEncoder(o.stdout).Encode(event)
}

func boundedOutputError(err error) string {
	message := err.Error()
	if len(message) > 1024 {
		return message[:1024]
	}
	return message
}

// handlePublisherEvent is where the CLI handles publisher status and policy
// totals.
func handlePublisherEvent(ctx context.Context, tunnel *clientstate.Tunnel, output *publishOutput, event publisher.Event) error {
	switch event.Type {
	case publisher.EventRouteAssigned:
		return tunnel.SetRoute(ctx, event.RouteID, event.Hostname)
	case publisher.EventProvisioning:
		if err := tunnel.SetProvisioning(ctx, event.RouteVersion); err != nil {
			return err
		}
		return output.provisioning(event.Hostname, event.RouteVersion)
	case publisher.EventProvisioningStalled:
		return output.provisioningStalled(event.RouteVersion)
	case publisher.EventReady:
		if err := tunnel.SetReady(ctx, event.PublicURL, event.RouteVersion); err != nil {
			return err
		}
		return output.ready(event.PublicURL, event.RouteVersion)
	case publisher.EventDraining:
		return tunnel.SetDraining(context.WithoutCancel(ctx))
	case publisher.EventTransportFallback:
		return output.transportFallback(event.RouteVersion, string(event.Transport))
	case publisher.EventIPPolicyDenials:
		return output.blockedVisitors(event.RouteVersion, event.PolicyDenials)
	}
	return nil
}
