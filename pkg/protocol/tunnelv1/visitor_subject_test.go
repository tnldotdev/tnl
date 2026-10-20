package tunnelv1

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestVisitorSubjectVariants(t *testing.T) {
	human := VisitorSubject{Kind: VisitorHumanDevice, IdentityID: opaqueid.IdentityPrefix + strings.Repeat("A", 22), DeviceID: opaqueid.VisitorDevicePrefix + strings.Repeat("B", 22)}
	workload := VisitorSubject{Kind: VisitorWorkloadSession, WorkloadSessionID: "wls_" + strings.Repeat("C", 22)}
	for _, s := range []VisitorSubject{human, workload} {
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var decoded VisitorSubject
		if err = json.Unmarshal(data, &decoded); err != nil || decoded != s {
			t.Fatal("subject did not round trip", err)
		}
	}
	for _, bad := range []VisitorSubject{{}, {Kind: VisitorHumanDevice, IdentityID: human.IdentityID}, {Kind: VisitorHumanDevice, IdentityID: human.IdentityID, DeviceID: human.DeviceID, WorkloadSessionID: workload.WorkloadSessionID}, {Kind: VisitorWorkloadSession, WorkloadSessionID: workload.WorkloadSessionID, IdentityID: human.IdentityID}, {Kind: "publisher", WorkloadSessionID: workload.WorkloadSessionID}, {Kind: VisitorWorkloadSession, WorkloadSessionID: strings.Repeat("C", 256)}} {
		if bad.Validate() == nil {
			t.Fatal("accepted mixed or invalid visitor subject")
		}
	}
}
