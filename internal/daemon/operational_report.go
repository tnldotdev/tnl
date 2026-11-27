package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/relay"
)

// operationalReport is an observation-only value. it contains no error handles,
// socket addresses, source proofs, credentials, or free-form cause text. changing
// this snapshot cannot replace or mutate the error sent to production reporting.
type operationalReport struct {
	operation                                    failure.Operation
	reason                                       failure.Reason
	service, run, visitor                        string
	number                                       uint64
	candidate                                    string
	candidateNumber                              uint64
	admitted                                     bool
	phase, denial                                string
	admissionCause, admissionOnly                bool
	copyMethodsObserved                          bool
	result, operationResult, copyResult, cleanup causeSnapshot
}

type causeSnapshot struct {
	nodes     []causeNode
	truncated bool
}

type causeNode struct {
	kind                                       string
	parent                                     int
	eof, canceled, deadline, admission         bool
	native                                     string
	streamID                                   int64
	code                                       uint64
	remote                                     bool
	copyOperation, copyEndpoint, copyDirection string
}

func (d *daemon) reportOperationalError(ctx context.Context, operation failure.Operation, reason failure.Reason, cause error, extra ...slog.Attr) {
	// the original report is unconditional and receives the original error.
	// the observer runs afterward and receives only a detached safe projection.
	ctx, fields := forwardingLogFields(ctx, cause)
	operatorlog.ReportFields(ctx, operation, reason, "", cause, append(fields, extra...)...)
	if cause != nil && d.observeOperationalReport != nil {
		d.observeOperationalReport(snapshotOperationalReport(operation, reason, cause))
	}
}

func snapshotOperationalReport(operation failure.Operation, reason failure.Reason, cause error) operationalReport {
	if specific, ok := failure.ReasonOf(cause); ok {
		reason = specific
	}
	result := operationalReport{
		operation: operation, reason: reason, phase: "process", result: snapshotCauses(cause),
		admissionCause: errors.Is(cause, ingress.ErrServiceAdmission), admissionOnly: failure.Only(cause, ingress.ErrServiceAdmission),
	}
	var forwarded *relay.ForwardingError
	var visitor *ingress.VisitorError
	switch {
	case errors.As(cause, &forwarded):
		result.service, result.run, result.visitor, result.number = forwarded.ForwardingScope()
		result.phase = forwarded.ForwardingPhase()
		result.copyMethodsObserved = forwarded.ForwardingCopyMethodsObserved()
		result.operationResult = snapshotCauses(forwarded.ForwardingOperation())
		result.copyResult = snapshotCauses(forwarded.ForwardingCopyResult())
		result.cleanup = snapshotCauses(forwarded.ForwardingCleanup())
	case errors.As(cause, &visitor):
		result.service, result.run, result.visitor, result.number = visitor.ForwardingScope()
		result.candidate, result.candidateNumber = visitor.ForwardingCandidate()
		result.phase, result.denial, result.admitted = visitor.ForwardingPhase(), visitor.ForwardingDenialReason(), visitor.ForwardingAdmitted()
		result.operationResult = snapshotCauses(visitor.ForwardingOperation())
		result.copyResult = snapshotCauses(visitor.ForwardingCopyResult())
		result.cleanup = snapshotCauses(visitor.ForwardingCleanup())
	default:
		result.operationResult = result.result
	}
	return result
}

// retain tree positions and exact typed native fields, not Error() strings.
// limits protect observation from an unusually large or cyclic cause graph.
func snapshotCauses(cause error) causeSnapshot {
	var result causeSnapshot
	var walk func(error, int, int)
	walk = func(err error, parent, depth int) {
		if err == nil {
			return
		}
		if len(result.nodes) == 128 || depth == 32 {
			result.truncated = true
			return
		}
		node := causeNode{kind: fmt.Sprintf("%T", err), parent: parent,
			eof: err == io.EOF, canceled: err == context.Canceled, deadline: err == context.DeadlineExceeded, admission: err == ingress.ErrServiceAdmission}
		switch native := err.(type) {
		case *quic.StreamError:
			node.native, node.streamID, node.code, node.remote = "stream", int64(native.StreamID), uint64(native.ErrorCode), native.Remote
		case *quic.ApplicationError:
			node.native, node.code, node.remote = "application", uint64(native.ErrorCode), native.Remote
		case *quic.TransportError:
			node.native, node.code, node.remote = "transport", uint64(native.ErrorCode), native.Remote
		}
		if step, ok := err.(interface {
			ForwardingCopyOperation() (string, string, string)
		}); ok {
			operation, endpoint, direction := step.ForwardingCopyOperation()
			// this is a consumer-owned observation interface, not permission to
			// export arbitrary strings supplied by another error implementation.
			if validCopyOperationLabels(operation, endpoint, direction) {
				node.copyOperation, node.copyEndpoint, node.copyDirection = operation, endpoint, direction
			} else {
				node.copyOperation = "unknown"
			}
		}
		index := len(result.nodes)
		result.nodes = append(result.nodes, node)
		switch wrapper := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range wrapper.Unwrap() {
				if len(result.nodes) == 128 {
					result.truncated = true
					break
				}
				walk(child, index, depth+1)
			}
		case interface{ Unwrap() error }:
			walk(wrapper.Unwrap(), index, depth+1)
		}
	}
	walk(cause, -1, 0)
	return result
}

func validCopyOperationLabels(operation, endpoint, direction string) bool {
	if endpoint != "ingress" && endpoint != "publisher" {
		return false
	}
	if operation == "copy_abort_close" {
		return direction == "not_applicable"
	}
	if operation != "read" && operation != "write" && operation != "half_close" {
		return false
	}
	toPublisher := operation == "read" && endpoint == "ingress" || operation != "read" && endpoint == "publisher"
	if toPublisher {
		return direction == "visitor_to_publisher"
	}
	return direction == "publisher_to_visitor"
}
