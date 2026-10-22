package publisherjob

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestJobStatusRejectsUnknownObservationAndPersistedState(t *testing.T) {
	r := testRegistry(t)
	job, identity, private := fixture(t, "status")
	if err := r.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	if err := r.status(t.Context(), job.ID, 1, Status{State: JobStatus("unrecognized")}); !errors.Is(err, ErrScope) {
		t.Fatal("unknown observation reached persisted status", err)
	}
	if err := r.status(t.Context(), job.ID, 1, Status{State: JobTargetUnavailable}); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].Status.State != JobTargetUnavailable {
		t.Fatal(jobs, err)
	}
	value, err := json.Marshal(jobs[0].Status)
	if err != nil || string(value) != `{"state":"target unavailable"}` {
		t.Fatal("stored status encoding changed", string(value), err)
	}
	if err := r.update(t.Context(), func(jobs *[]Job) error {
		(*jobs)[0].Status.State = "unrecognized"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.List(t.Context()); !errors.Is(err, ErrUnsafeState) {
		t.Fatal("unknown stored state was accepted", err)
	}
}
