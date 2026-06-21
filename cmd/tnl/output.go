package main

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/0xcadams/tnl/internal/coreclient"
)

type publicEvent struct {
	SchemaVersion int        `json:"schema_version"`
	Type          string     `json:"type"`
	Cursor        uint64     `json:"cursor"`
	Target        string     `json:"target,omitempty"`
	URL           string     `json:"url,omitempty"`
	Generation    uint64     `json:"generation,omitempty"`
	Message       string     `json:"message,omitempty"`
	Retryable     *bool      `json:"retryable,omitempty"`
	RetryAt       *time.Time `json:"retry_at,omitempty"`
	Reason        string     `json:"reason,omitempty"`
}

type publicOutput struct {
	mode    string
	stdout  io.Writer
	stderr  io.Writer
	mu      sync.Mutex
	cursor  uint64
	printed bool
}

func newPublicOutput(mode string, stdout, stderr io.Writer) (*publicOutput, error) {
	if mode != "human" && mode != "ndjson" {
		return nil, errors.New("output must be human or ndjson")
	}
	return &publicOutput{mode: mode, stdout: stdout, stderr: stderr}, nil
}

func (o *publicOutput) starting(target string) error {
	if o.mode == "human" {
		return nil
	}
	return o.emit(publicEvent{Type: "starting", Target: target})
}

func (o *publicOutput) ready(url string, generation uint64) error {
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
	return o.emitLocked(publicEvent{Type: "ready", URL: url, Generation: generation})
}

func (o *publicOutput) failed(err error) error {
	if o.mode == "human" {
		return nil
	}
	retryable := errors.Is(err, coreclient.ErrUnavailable) || errors.Is(err, coreclient.ErrRateLimited)
	event := publicEvent{Type: "error", Message: boundedOutputError(err), Retryable: &retryable}
	var limited *coreclient.RateLimitError
	if errors.As(err, &limited) && limited.RetryAfter > 0 {
		retryAt := time.Now().Add(limited.RetryAfter).UTC()
		event.RetryAt = &retryAt
	}
	return o.emit(event)
}

func (o *publicOutput) stopped() error {
	if o.mode == "human" {
		return nil
	}
	return o.emit(publicEvent{Type: "stopped", Reason: "canceled"})
}

func (o *publicOutput) emit(event publicEvent) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.emitLocked(event)
}

func (o *publicOutput) emitLocked(event publicEvent) error {
	// Keep cursor assignment and encoding in one critical section.
	o.cursor++
	event.SchemaVersion = 1
	event.Cursor = o.cursor
	return json.NewEncoder(o.stdout).Encode(event)
}

func boundedOutputError(err error) string {
	message := err.Error()
	if len(message) > 1024 {
		return message[:1024]
	}
	return message
}
