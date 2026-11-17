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
			t.Logf("current forwarding report index=%d origin=%s history=%s service_id=%s service_run_id=%s run_number=%d visitor_connection_id=%s candidate_run_id=%s candidate_run_number=%d phase=%s admitted=%t reason=%s admission_only=%t",
				index, origin, history.kind, report.service, report.run, report.number, report.visitor, report.candidate, report.candidateNumber,
				report.phase, report.admitted, report.reason, report.admissionOnly)
		}
		for _, group := range []struct {
			name   string
			causes causeSnapshot
		}{{"result", report.result}, {"operation_result", report.operationResult}, {"copy_result_including_abort_cleanup", report.copyResult}, {"final_physical_cleanup", report.cleanup}} {
			for nodeIndex, cause := range group.causes.nodes {
				t.Logf("current forwarding cause report=%d group=%s node=%d parent=%d type=%s native=%s stream_id=%d code=%d remote=%t eof=%t canceled=%t deadline=%t admission=%t",
					index, group.name, nodeIndex, cause.parent, cause.kind, cause.native, cause.streamID, cause.code, cause.remote,
					cause.eof, cause.canceled, cause.deadline, cause.admission)
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
