package serviceaudit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func serviceDenialObservation() Observation {
	return Observation{
		EventID: NewID(), ServiceID: "svc_0123456789ABCDEFGHIJKL", ServiceKind: "service",
		VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", SourceIP: "192.0.2.4",
		EventType: "connection.open", Outcome: "denied", Reason: "capacity", OccurredAt: time.Now().UTC(),
	}
}

func TestServiceLevelDenialKeepsReceiptAndSourceWithoutInventingRun(t *testing.T) {
	for _, reason := range []string{"capacity", "unavailable", "invalid_request"} {
		t.Run(reason, func(t *testing.T) {
			denied := serviceDenialObservation()
			denied.Reason = reason
			if err := denied.Validate(); err != nil {
				t.Fatal("service-level denial required an invented run", err)
			}
			wire, err := APIObservations(Batch{Events: []Observation{denied}})
			if err != nil || len(wire) != 1 {
				t.Fatal("service-level denial could not be serialized", err)
			}
			got := wire[0]
			if got.ServiceId != denied.ServiceID || got.VisitorConnectionId != denied.VisitorConnectionID ||
				got.SourceIp == nil || *got.SourceIp != denied.SourceIP || got.RunId != "" || got.RunNumber != 0 ||
				got.PairId != nil || got.DeliveryGeneration != 0 || string(got.Outcome) != "denied" ||
				string(got.EventType) != "connection.open" || got.Reason == nil || string(*got.Reason) != reason {
				t.Fatal("serialization changed the denial's admission scope or invented a selected run", got)
			}
		})
	}
}

func TestRunlessServiceObservationCannotClaimTrafficOrConnectorAuthority(t *testing.T) {
	for name, change := range map[string]func(*Observation){
		"allowed open":       func(o *Observation) { o.Outcome = "allowed" },
		"forwarded open":     func(o *Observation) { o.Outcome = "forwarded" },
		"closed open":        func(o *Observation) { o.Outcome = "closed" },
		"failed open":        func(o *Observation) { o.Outcome = "failed" },
		"denied close":       func(o *Observation) { o.EventType = "connection.close" },
		"allowed close":      func(o *Observation) { o.EventType, o.Outcome = "connection.close", "allowed" },
		"closed connection":  func(o *Observation) { o.EventType, o.Outcome = "connection.close", "closed" },
		"failed close":       func(o *Observation) { o.EventType, o.Outcome = "connection.close", "failed" },
		"denied request":     func(o *Observation) { o.EventType = "http.decision" },
		"allowed request":    func(o *Observation) { o.EventType, o.Outcome = "http.decision", "allowed" },
		"failed request":     func(o *Observation) { o.EventType, o.Outcome = "http.decision", "failed" },
		"connector":          func(o *Observation) { o.PairID, o.DeliveryGeneration = "cpp_0123456789ABCDEFGHIJKL", 1 },
		"connector revision": func(o *Observation) { o.DeliveryGeneration = 1 },
		"partial run ID":     func(o *Observation) { o.RunID = "srun_0123456789ABCDEFGHIJKL" },
		"partial run number": func(o *Observation) { o.RunNumber = 1 },
		"missing service":    func(o *Observation) { o.ServiceID = "" },
		"wrong service ID":   func(o *Observation) { o.ServiceID = "url_0123456789ABCDEFGHIJKL" },
		"unknown kind":       func(o *Observation) { o.ServiceKind = "unknown" },
		"missing receipt":    func(o *Observation) { o.VisitorConnectionID = "" },
		"invalid receipt":    func(o *Observation) { o.VisitorConnectionID = "vc_invalid" },
		"missing source":     func(o *Observation) { o.SourceIP = "" },
		"invalid source":     func(o *Observation) { o.SourceIP = "not an address" },
		"source network":     func(o *Observation) { o.SourceIP = "192.0.2.0/24" },
		"mapped source":      func(o *Observation) { o.SourceIP = "::ffff:192.0.2.4" },
		"zoned source":       func(o *Observation) { o.SourceIP = "fe80::1%en0" },
		"missing event":      func(o *Observation) { o.EventID = "" },
		"missing time":       func(o *Observation) { o.OccurredAt = time.Time{} },
		"unknown reason":     func(o *Observation) { o.Reason = "unreviewed details" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := serviceDenialObservation()
			change(&bad)
			if err := bad.Validate(); err != ErrInvalid {
				t.Fatal("run-less observation escaped the denied-open exception", err, bad)
			}
			if wire, err := APIObservations(Batch{Events: []Observation{bad}}); err != ErrInvalid || wire != nil {
				t.Fatal("invalid run-less observation reached the API", wire, err)
			}
		})
	}
}

func TestServiceLevelDenialQueueRetriesSameBoundedObservation(t *testing.T) {
	denied := serviceDenialObservation()
	var received []Observation
	queue, err := NewQueue(t.Context(), QueueConfig{
		Capacity: 1, BatchSize: 1, FlushInterval: time.Hour, RetryMin: time.Millisecond, RetryMax: time.Millisecond,
		Report: func(_ context.Context, batch Batch) error {
			if len(batch.Events) != 1 {
				t.Error("service denial batch exceeded its bound", len(batch.Events))
				return ErrRejected
			}
			received = append(received, batch.Events[0])
			if len(received) == 1 {
				return errors.New("acknowledgement lost")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !queue.Observe(denied) {
		t.Fatal("queue discarded a service-level denial")
	}
	cleanup, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := queue.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	if len(received) != 2 || received[0] != denied || received[1] != denied {
		t.Fatal("retry changed the denial's event ID, receipt, source, timestamp, or run-less scope", received)
	}
	if count, bytes := queue.Pending(); count != 0 || bytes != 0 {
		t.Fatal("service denial retained queue capacity after joined shutdown", count, bytes)
	}
}

func TestServiceLevelDenialAllowsOnlyPendingReceiptReasons(t *testing.T) {
	for _, reason := range []string{"", "ip_policy", "draining", "authorization", "forwarding", "closed", "revoked", "expired", "cancelled"} {
		t.Run(reason, func(t *testing.T) {
			denied := serviceDenialObservation()
			denied.Reason = reason
			if err := denied.Validate(); err != ErrInvalid {
				t.Fatal("run-less denial claimed a decision outside its pending receipt", reason, err)
			}
			if wire, err := APIObservations(Batch{Events: []Observation{denied}}); err != ErrInvalid || wire != nil {
				t.Fatal("unsupported pending receipt reason reached the API", wire, err)
			}
			// this restriction does not change exact-run denials.
			denied.RunID, denied.RunNumber = "srun_0123456789ABCDEFGHIJKL", 1
			if err := denied.Validate(); err != nil {
				t.Fatal("pending receipt reasons restricted an exact-run event", reason, err)
			}
		})
	}
}
