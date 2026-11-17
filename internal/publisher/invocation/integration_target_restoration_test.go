package invocation

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPreparationRejectsConflictingSavedHandlerTarget(t *testing.T) {
	for _, test := range integrationIntentCases {
		hostname, intent := test.hostname, test.intent
		t.Run(hostname, func(t *testing.T) {
			f := newServiceSetupFixture(t, hostname)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, saved, err := nativeIntegrationConfig(ctx, f.services, hostname, intent, nil)
			if err != nil {
				t.Fatal("prepare original handler service", err)
			}
			configured, digest, err := f.services.routes.GetServiceConfiguration(ctx, saved.Id)
			if err != nil || configured == nil || configured.Target != string(intent) {
				t.Fatal("original integration did not save its handler placeholder", err)
			}
			configured.Target = "http://127.0.0.1:3000"
			// commit the conflict through the current management client, not
			// a fabricated preparation response or a retired purpose field.
			conflicting, err := f.services.routes.ConfigureService(ctx, saved.Id, controlv1.UpdateServiceRequest{
				ExpectedTrustRevision: saved.TrustRevision, ExpectedConfigurationDigest: &digest,
				ExpectedPublisherPool: new(saved.PublisherPool), PublisherPool: saved.PublisherPool,
				Protocol: saved.Protocol, TargetTls: saved.TargetTls, Configuration: configured})
			if err != nil || conflicting.Id != saved.Id {
				t.Fatal("save conflicting integration target", err)
			}
			before, err := json.Marshal(f.declaration)
			if err != nil {
				t.Fatal(err)
			}
			public := bytes.Clone(f.public)
			creates, updates, changes := f.creates, f.updates, f.changes
			enrollments, redemptions, runs := f.enrollments, f.redemptions, f.runs
			cfg, selected, err := nativeIntegrationConfig(ctx, f.services, hostname, intent, nil)
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Error("integration preparation accepted a conflicting saved handler target or lost its invalid-response reason", err)
			}
			if cfg.Control != nil || cfg.Access != nil || cfg.ServiceID != "" || selected.Id != "" {
				t.Error("conflicting handler target produced serving authority")
			}
			after, marshalErr := json.Marshal(f.declaration)
			if marshalErr != nil || !bytes.Equal(before, after) || !bytes.Equal(public, f.public) ||
				f.declaration.Target != configured.Target || f.saved.Id != saved.Id ||
				f.creates != creates || f.updates != updates || f.changes != changes ||
				f.enrollments != enrollments || f.redemptions != redemptions || f.runs != runs {
				t.Error("rejected integration preparation rewrote the saved conflict or changed service/key authority", marshalErr)
			}
		})
	}
}
