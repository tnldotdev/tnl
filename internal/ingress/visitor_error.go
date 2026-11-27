package ingress

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// VisitorError preserves diagnostic scope without treating a rejected candidate
// as a selected or admitted run. all original result causes remain unwrap-able.
type VisitorError struct {
	service, run, visitor      string
	number                     uint64
	candidate                  string
	candidateNumber            uint64
	admitted                   bool
	phase, denial              string
	operation, copyResult      error
	cleanup, result            error
	hello                      [16]byte
	previous                   []RelayAttempt
	last                       RelayAttempt
	span                       trace.SpanContext
	ingressRun                 string
	sent, returned             int64
	lastProgress, closeTrigger string
}

// RelayAttempt describes one actual opening, including a failed preferred relay
// before fallback. duration excludes later copying and teardown.
type RelayAttempt struct {
	RelayID, RelayRunID, PublisherConnectionID string
	Slot                                       int
	AssignmentRevision                         int64
	Elapsed, Budget                            time.Duration
	Step                                       string
	Committed                                  bool
	Err                                        error
}

func (e *VisitorError) ClientHelloID() [16]byte         { return e.hello }
func (e *VisitorError) SpanContext() trace.SpanContext  { return e.span }
func (e *VisitorError) IngressRunID() string            { return e.ingressRun }
func (e *VisitorError) Forwarded() (int64, int64)       { return e.sent, e.returned }
func (e *VisitorError) CloseProgress() (string, string) { return e.lastProgress, e.closeTrigger }
func (e *VisitorError) RelayAttempts() []RelayAttempt {
	if e.last.Step == "" {
		return nil
	}
	attempts := make([]RelayAttempt, len(e.previous)+1)
	copy(attempts, e.previous)
	attempts[len(e.previous)] = e.last
	return attempts
}

func (*VisitorError) Error() string      { return "ingress: visitor connection failed" }
func (e *VisitorError) GoString() string { return e.Error() }
func (e *VisitorError) Unwrap() error    { return e.result }

func (e *VisitorError) ForwardingScope() (service, run, visitor string, number uint64) {
	return e.service, e.run, e.visitor, e.number
}

func (e *VisitorError) ForwardingCandidate() (run string, number uint64) {
	return e.candidate, e.candidateNumber
}

func (e *VisitorError) ForwardingAdmitted() bool       { return e.admitted }
func (e *VisitorError) ForwardingPhase() string        { return e.phase }
func (e *VisitorError) ForwardingDenialReason() string { return e.denial }
func (e *VisitorError) ForwardingOperation() error     { return e.operation }
func (e *VisitorError) ForwardingCopyResult() error    { return e.copyResult }
func (e *VisitorError) ForwardingCleanup() error       { return e.cleanup }

// one accepted connection owns this diagnostic carrier through physical release.
// concurrent capacity and routing stops write only their atomic flags. none
// of these values is read by authorization, selection, metering or policy.
type visitorDiagnostic struct {
	VisitorError
	admitted       atomic.Bool
	routingStopped atomic.Bool
}

type visitorDiagnosticKey struct{}

func visitorDiagnosticFrom(ctx context.Context) *visitorDiagnostic {
	value, _ := ctx.Value(visitorDiagnosticKey{}).(*visitorDiagnostic)
	return value
}

func (d *visitorDiagnostic) finish(operation, release error) error {
	if operation == nil && release == nil {
		return nil
	}
	result := d.VisitorError
	result.operation, result.result = operation, errors.Join(operation, release)
	result.cleanup = errors.Join(result.cleanup, release)
	result.admitted = d.admitted.Load()
	return &result
}
