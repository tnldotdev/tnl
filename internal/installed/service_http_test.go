package installed

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestInstalledJobsRejectRetiredPublicationFieldsWithoutChangingState(t *testing.T) {
	for _, field := range []string{`"public_url_id":""`, `"target_tls_name":"target.example"`, `"target_ca_pem":""`, `"limits":{}`, `"verify_readiness":true`} {
		r := testRegistry(t)
		job, _, _ := fixture(t, "web")
		job.Enabled, job.Revision = true, 1
		value, err := json.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		value = append(append(value[:len(value)-1], ','), []byte(field+"}")...)
		document := append(append([]byte{'['}, value...), ']')
		if err := r.database.SavePublisherJobRegistry(t.Context(), document); err != nil {
			t.Fatal(err)
		}
		if _, err := r.List(t.Context()); !errors.Is(err, ErrUnsafeState) {
			t.Fatal("retired job metadata was ignored or converted", field, err)
		}
		stored, found, err := r.database.PublisherJobRegistry(t.Context())
		if err != nil || !found || string(stored) != string(document) {
			t.Fatal("rejection discarded or replaced the old registry", err)
		}
	}
}

func TestInstalledJobsRejectRetiredAddressObservation(t *testing.T) {
	registry := testRegistry(t)
	job, _, _ := fixture(t, "web")
	job.Revision = 1
	encoded, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	document["status"] = map[string]any{"state": "ready", "public_url": "https://retired.example"}
	encoded, err = json.Marshal([]any{document})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.database.SavePublisherJobRegistry(t.Context(), encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.List(t.Context()); !errors.Is(err, ErrUnsafeState) {
		t.Fatal("retired status field was imported", err)
	}
	stored, found, err := registry.database.PublisherJobRegistry(t.Context())
	if err != nil || !found || string(stored) != string(encoded) {
		t.Fatal("rejection rewrote the old snapshot", err)
	}
}
