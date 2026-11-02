package serviceaudit

import (
	"testing"
	"time"
)

func TestNativeObservationRequiresInstalledRunScope(t *testing.T) {
	opened := Observation{EventID: NewID(), OccurredAt: time.Now(), ServiceID: "svc_0123456789ABCDEFGHIJKL", ServiceKind: "service", RunID: "srun_0123456789ABCDEFGHIJKL", RunNumber: 1, PairID: "cpp_0123456789ABCDEFGHIJKL", VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", SourceIP: "192.0.2.9", EventType: "connection.open", Outcome: "allowed"}
	if err := opened.Validate(); err != nil {
		t.Fatal(err)
	}
	closed := opened
	closed.EventID, closed.EventType, closed.Outcome, closed.Reason = NewID(), "connection.close", "closed", "closed"
	if closed.Validate() != nil || closed.EventID == opened.EventID || closed.VisitorConnectionID != opened.VisitorConnectionID {
		t.Fatal("close lost correlation or reused an event identity")
	}
	for name, change := range map[string]func(*Observation){
		"missing run":        func(o *Observation) { o.RunID = "" },
		"missing run number": func(o *Observation) { o.RunNumber = 0 },
		"missing source":     func(o *Observation) { o.SourceIP = "" },
		"wrong kind":         func(o *Observation) { o.ServiceKind = "public_url" },
		"wrong pair":         func(o *Observation) { o.PairID = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := opened
			change(&bad)
			if bad.Validate() != ErrInvalid {
				t.Fatal("accepted invalid native scope")
			}
		})
	}
}
