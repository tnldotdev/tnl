package daemon

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// histories come from exact durable events, never HTTP paths or body matching.
type heldForwardingHistory struct {
	kind, service, run string
	number             uint64
}

func validateHeldForwardingReport(report operationalReport, history heldForwardingHistory) error {
	if report.operation != "forward through relay" && report.operation != "serve ingress connection" {
		return errors.New("callback did not originate at the forwarding report owners")
	}
	if !opaqueid.Valid(report.service, opaqueid.ServicePrefix) || !opaqueid.Valid(report.visitor, opaqueid.VisitorConnectionPrefix) ||
		report.service != history.service || len(report.result.nodes) == 0 {
		return errors.New("callback lost its exact durable service/visitor scope")
	}
	for _, result := range []causeSnapshot{report.result, report.operationResult, report.copyResult, report.cleanup} {
		if result.truncated {
			return errors.New("callback cause tree is incomplete")
		}
	}
	if err := validateHeldCopyOperations(report); err != nil {
		return err
	}
	if history.kind == "source-denied" {
		if report.operation != "serve ingress connection" || report.run != "" || report.number != 0 ||
			report.candidate != history.run || report.candidateNumber != history.number || report.admitted ||
			report.phase != "selection" || report.denial != "ip_policy" || !report.admissionCause || len(report.copyResult.nodes) != 0 {
			return errors.New("source denial invented an admitted run or lost its exact candidate")
		}
		return nil
	}
	if history.kind != "held" && history.kind != "overflow" {
		return errors.New("callback has no durable held or overflow visitor history")
	}
	if report.run != history.run || report.number != history.number || report.candidate != "" || report.candidateNumber != 0 ||
		(report.phase != "open" && report.phase != "opening" && report.phase != "copy") {
		return errors.New("callback crossed durable service-run histories")
	}
	if history.kind == "held" && report.operation == "serve ingress connection" && !report.admitted {
		return errors.New("completed held visitor lost its admitted capacity fact")
	}
	return nil
}

// follow only recorded parent positions. a native code (including zero), nearby
// report, or final close never supplies a missing returning-method observation.
func heldCopyOperation(causes causeSnapshot, index int) (operation, endpoint, direction string) {
	for depth := 0; index >= 0 && index < len(causes.nodes) && depth < 32; depth++ {
		node := causes.nodes[index]
		if validCopyOperationLabels(node.copyOperation, node.copyEndpoint, node.copyDirection) {
			return node.copyOperation, node.copyEndpoint, node.copyDirection
		}
		if node.copyOperation != "" {
			break
		}
		index = node.parent
	}
	return "UNKNOWN", "UNKNOWN", "UNKNOWN"
}

func validateHeldCopyOperations(report operationalReport) error {
	for _, node := range report.cleanup.nodes {
		if node.copyOperation != "" {
			return errors.New("copy marker crossed into final physical cleanup")
		}
	}
	for i, node := range report.copyResult.nodes {
		if node.copyOperation != "" && !validCopyOperationLabels(node.copyOperation, node.copyEndpoint, node.copyDirection) {
			return errors.New("copy result contains an invalid operation marker")
		}
		if node.copyOperation != "" && !report.copyMethodsObserved {
			return errors.New("unobserved copy claimed an exact returning method")
		}
		operation, _, _ := heldCopyOperation(report.copyResult, i)
		if report.copyMethodsObserved && node.native != "" && operation == "UNKNOWN" {
			return errors.New("observed native copy cause lost its returning method")
		}
	}
	return nil
}

func assertHeldForwardingReports(t *testing.T, recorder *eventRecorder[operationalReport], histories map[string]heldForwardingHistory, complete bool) {
	t.Helper()
	reports, err := recorder.snapshot()
	if err != nil {
		t.Fatal("forwarding recorder did not retain its observations")
	}
	denials := make(map[string]int)
	relayReports, ingressReports := 0, 0
	for index, report := range reports {
		history := histories[report.visitor]
		if complete {
			if err := validateHeldForwardingReport(report, history); err != nil {
				// only authored validation text, never any recorded raw cause.
				t.Error(err)
			}
		}
		origin := "ingress.OnError"
		if report.operation == "forward through relay" {
			origin = "relay.Report"
			relayReports++
		} else {
			ingressReports++
		}
		if history.kind == "source-denied" {
			denials[report.visitor]++
		}
		if !opaqueid.Valid(report.service, opaqueid.ServicePrefix) || !opaqueid.Valid(report.visitor, opaqueid.VisitorConnectionPrefix) ||
			report.run != "" && !opaqueid.Valid(report.run, opaqueid.ServiceRunPrefix) ||
			report.candidate != "" && !opaqueid.Valid(report.candidate, opaqueid.ServiceRunPrefix) {
			t.Logf("current forwarding report index=%d origin=%s scope=unavailable", index, origin)
		} else {
			t.Logf("current forwarding report index=%d origin=%s history=%s service_id=%s service_run_id=%s run_number=%d visitor_connection_id=%s candidate_run_id=%s candidate_run_number=%d phase=%s admitted=%t reason=%s admission_only=%t copy_methods_observed=%t",
				index, origin, history.kind, report.service, report.run, report.number, report.visitor, report.candidate, report.candidateNumber,
				report.phase, report.admitted, report.reason, report.admissionOnly, report.copyMethodsObserved)
		}
		for _, group := range []struct {
			name   string
			causes causeSnapshot
		}{{"result", report.result}, {"operation_result", report.operationResult}, {"copy_result_including_abort_cleanup", report.copyResult}, {"final_physical_cleanup", report.cleanup}} {
			for nodeIndex, cause := range group.causes.nodes {
				operation, endpoint, direction := heldCopyOperation(group.causes, nodeIndex)
				t.Logf("current forwarding cause report=%d group=%s node=%d parent=%d type=%s native=%s stream_id=%d code=%d remote=%t eof=%t canceled=%t deadline=%t admission=%t copy_operation=%s copy_endpoint=%s copy_direction=%s",
					index, group.name, nodeIndex, cause.parent, cause.kind, cause.native, cause.streamID, cause.code, cause.remote,
					cause.eof, cause.canceled, cause.deadline, cause.admission, operation, endpoint, direction)
			}
		}
	}
	if complete {
		for visitor, history := range histories {
			if history.kind == "source-denied" && denials[visitor] != 1 {
				t.Error("real source denial did not produce exactly one observed ingress report")
			}
		}
	}
	t.Logf("current forwarding reports joined=%t relay=%d ingress=%d total=%d", complete, relayReports, ingressReports, len(reports))
}

func TestHeldForwardingCopyOperationsUseOnlyExactAncestorOrExplicitUnknown(t *testing.T) {
	native := &causeNode{kind: "*quic.StreamError", native: "stream", streamID: 5, code: 0, remote: true, parent: 1}
	causes := causeSnapshot{nodes: []causeNode{
		{kind: "*errors.joinError", parent: -1},
		{kind: "*relay.copyOperationError", parent: 0, copyOperation: "half_close", copyEndpoint: "publisher", copyDirection: "visitor_to_publisher"},
		*native,
		{kind: "*errors.errorString", parent: 0},
	}}
	report := operationalReport{copyMethodsObserved: true, copyResult: causes}
	if err := validateHeldCopyOperations(report); err != nil {
		t.Fatal(err)
	}
	op, end, dir := heldCopyOperation(causes, 2)
	if op != "half_close" || end != "publisher" || dir != "visitor_to_publisher" {
		t.Fatal("native cause lost its exact observed ancestor")
	}
	op, end, dir = heldCopyOperation(causes, 3)
	if op != "UNKNOWN" || end != "UNKNOWN" || dir != "UNKNOWN" {
		t.Fatal("unmarked independent cause borrowed provenance")
	}
	report.copyMethodsObserved = false
	if validateHeldCopyOperations(report) == nil {
		t.Fatal("unobserved copy claimed provenance")
	}
	report.copyResult = causeSnapshot{nodes: []causeNode{{native: "stream", code: 0, remote: true, parent: -1}}}
	if err := validateHeldCopyOperations(report); err != nil {
		t.Fatal("fallback must remain explicitly unknown", err)
	}
	op, _, _ = heldCopyOperation(report.copyResult, 0)
	if op != "UNKNOWN" {
		t.Fatal("code zero alone supplied provenance")
	}
	report.copyMethodsObserved = true
	if validateHeldCopyOperations(report) == nil {
		t.Fatal("observed native cause silently lost provenance")
	}
	report.copyResult, report.cleanup = causes, causes
	if validateHeldCopyOperations(report) == nil {
		t.Fatal("final physical close was marked as a copy operation")
	}
}

func TestHeldForwardingReportCorrelationKeepsDenialsRunlessAndCleanupIndependent(t *testing.T) {
	service := "svc_aaaaaaaaaaaaaaaaaaaaaa"
	run := "srun_aaaaaaaaaaaaaaaaaaaaaa"
	visitor := "vc_aaaaaaaaaaaaaaaaaaaaaa"
	history := heldForwardingHistory{kind: "source-denied", service: service, run: run, number: 3}
	report := operationalReport{
		operation: "serve ingress connection", reason: failure.ServerIngressFailed,
		service: service, visitor: visitor, candidate: run, candidateNumber: 3, phase: "selection", denial: "ip_policy", admissionCause: true,
		result: snapshotCauses(errors.New("secret denied socket material")), cleanup: snapshotCauses(errors.New("independent cleanup")),
	}
	if err := validateHeldForwardingReport(report, history); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*operationalReport){
		func(r *operationalReport) { r.run, r.number = run, 3 },
		func(r *operationalReport) { r.admitted = true },
		func(r *operationalReport) { r.candidateNumber++ },
		func(r *operationalReport) { r.service = "svc_bbbbbbbbbbbbbbbbbbbbbb" },
		func(r *operationalReport) { r.copyResult = r.result },
		func(r *operationalReport) { r.cleanup.truncated = true },
	} {
		changed := report
		change(&changed)
		if validateHeldForwardingReport(changed, history) == nil {
			t.Fatal("callback correlation accepted a contradictory or incomplete report")
		}
	}
}
