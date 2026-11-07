package service

import "testing"

func TestConnectorAdmissionRetirementRetainsCapacityPhase(t *testing.T) {
	for _, test := range []struct {
		name     string
		state    connectorAdmissionState
		charged  bool
		admitted bool
		ready    bool
	}{
		{"reserved", reservedConnectorAdmission{}, false, false, false},
		{"charged", chargedConnectorAdmission{}, true, false, false},
		{"admitted", admittedConnectorAdmission{}, true, true, false},
		{"ready", readyConnectorAdmission{}, true, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := &connectorAdmission{state: test.state}
			if a.chargedLocked() != test.charged || a.admittedLocked() != test.admitted || a.readyLocked() != test.ready {
				t.Fatal("active capacity phase does not match its charge")
			}
			a.retireLocked()
			a.retireLocked()
			if !a.retiringLocked() || a.chargedLocked() != test.charged || a.admittedLocked() != test.admitted || a.readyLocked() != test.ready {
				t.Fatal("retirement released capacity before physical close joined")
			}
			a.state = releasedConnectorAdmission{}
			a.retireLocked()
			if a.retiringLocked() || a.chargedLocked() || a.admittedLocked() || a.readyLocked() {
				t.Fatal("released admission was revived")
			}
		})
	}
}
