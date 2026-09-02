package main

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/serverclient"
)

type publishEvent struct {
	SchemaVersion int        `json:"schema_version"`
	Type          string     `json:"type"`
	Cursor        uint64     `json:"cursor"`
	TunnelID      string     `json:"tunnel_id"`
	Target        string     `json:"target,omitempty"`
	URL           string     `json:"url,omitempty"`
	Version       uint64     `json:"version,omitempty"`
	IP            string     `json:"ip,omitempty"`
	Message       string     `json:"message,omitempty"`
	Retryable     *bool      `json:"retryable,omitempty"`
	RetryAt       *time.Time `json:"retry_at,omitempty"`
	Reason        string     `json:"reason,omitempty"`
}

type publishOutput struct {
	mode     string
	stdout   io.Writer
	stderr   io.Writer
	mu       sync.Mutex
	cursor   uint64
	tunnelID string
	printed  bool
}

func newPublishOutput(mode string, stdout, stderr io.Writer) (*publishOutput, error) {
	if mode != "human" && mode != "ndjson" {
		return nil, errors.New("output must be human or ndjson")
	}
	return &publishOutput{mode: mode, stdout: stdout, stderr: stderr}, nil
}

func (o *publishOutput) starting(tunnelID, target string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tunnelID = tunnelID
	if o.mode == "human" {
		return nil
	}
	return o.emitLocked(publishEvent{Type: "starting", Target: target})
}

func (o *publishOutput) ready(url string, version uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.mode == "human" {
		if o.printed {
			return nil
		}
		o.printed = true
		_, err := io.WriteString(o.stderr, url+"\n")
		return err
	}
	return o.emitLocked(publishEvent{Type: "ready", URL: url, Version: version})
}

func (o *publishOutput) currentIP(ip string) error {
	if o.mode == "human" {
		_, err := io.WriteString(o.stderr, "Current IP: "+ip+"\n")
		return err
	}
	return o.emit(publishEvent{Type: "current_ip", IP: ip})
}

func (o *publishOutput) failed(err error) error {
	if o.mode == "human" {
		return nil
	}
	retryable := errors.Is(err, serverclient.ErrUnavailable) || errors.Is(err, serverclient.ErrRateLimited)
	event := publishEvent{Type: "error", Message: boundedOutputError(err), Retryable: &retryable}
	var limited *serverclient.RateLimitError
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
