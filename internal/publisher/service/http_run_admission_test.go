package service

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPAdmissionBindsEachServingRunAndPreservesOwnerGuard(t *testing.T) {
	cfg, control, _ := setupSourceFixture(t)
	var seen []HTTPRun
	var ownerError error
	cfg.AdmitRequest = func(*http.Request) error { return ownerError }
	cfg.HTTPAdmitRequest = func(_ *http.Request, run HTTPRun) error {
		seen = append(seen, run)
		return nil
	}
	first, err := newManagedPrepared(control.prep, *control.approved, cfg)
	if err != nil {
		t.Fatal(err)
	}
	secondPreparation := control.prep
	secondPreparation.RunNumber++
	second, err := newManagedPrepared(secondPreparation, *control.approved, cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://"+control.prep.Hostname+"/callback?state=opaque", nil)
	for _, prepared := range []*Prepared{second, first} {
		if err := prepared.admitRequest(request); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 || seen[0].Number != secondPreparation.RunNumber ||
		seen[1] != (HTTPRun{ServiceID: control.prep.ServiceId, RunID: control.prep.ServiceRunId,
			Hostname: control.prep.Hostname, Number: control.prep.RunNumber}) {
		t.Fatal("HTTP admission captured another serving run", seen)
	}
	_, closeRun, err := configureServiceRun(t.Context(), cfg, first, control.setup, control, cfg.State, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeRun(); err != nil {
			t.Error(err)
		}
	}()
	frontend, ok := first.connectorHTTP.(HTTP)
	if !ok {
		t.Fatal("configured HTTP frontend has an unexpected owner")
	}
	if err := frontend.AdmitRequest(request); err != nil || len(seen) != 3 || seen[2] != seen[1] {
		t.Fatal("configured HTTP frontend lost its run-bound admission", err, seen)
	}
	ownerError = errors.New("registration replaced")
	for _, admit := range []func(*http.Request) error{first.admitRequest, frontend.AdmitRequest} {
		if err := admit(request); !errors.Is(err, ownerError) || len(seen) != 3 {
			t.Fatal("HTTP feature admission bypassed the current owner guard", err, seen)
		}
	}
	invalid := control.prep
	invalid.ServiceId = ""
	if _, err := newManagedPrepared(invalid, *control.approved, cfg); err == nil {
		t.Fatal("invalid preparation constructed HTTP admission")
	}
	nonHTTP := *control.approved
	nonHTTP.Protocol = controlv1.Tcp
	if _, err := newManagedPrepared(control.prep, nonHTTP, cfg); err == nil {
		t.Fatal("HTTP admission attached to a non-HTTP service")
	}
}
