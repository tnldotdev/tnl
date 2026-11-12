package supervisor

import (
	"testing"
)

func TestTelemetryInstallationPreservesInstallerChoiceForEveryJobKind(t *testing.T) {
	for _, kind := range []Kind{KindPublicURL, KindService, KindConnector, KindGroup} {
		for _, choice := range []string{"default", "disabled"} {
			t.Run(string(kind)+"/"+choice, func(t *testing.T) {
				options := testOptions(t)
				options.User = true
				registry, err := Open(t.Context(), options)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = registry.Close() })
				job, identity, key := kindFixture(t, kind)
				ctx := t.Context()
				job.TelemetryDisabled = choice == "disabled"
				// the receiving registry's preference is not the installer's choice.
				if err := registry.database.SetTelemetryEnabled(ctx, job.TelemetryDisabled); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case KindGroup:
					err = registry.InstallGroup(ctx, job, *job.GroupMember, key)
				case KindConnector:
					err = registry.InstallConnector(ctx, job)
				default:
					err = registry.Install(ctx, job, identity, key)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := registry.database.SetTelemetryEnabled(t.Context(), true); err != nil {
					t.Fatal(err)
				}
				if err := registry.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := Open(t.Context(), options)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				jobs, err := reopened.List(t.Context())
				if err != nil || len(jobs) != 1 || jobs[0].TelemetryDisabled != (choice != "default") {
					t.Fatalf("saved telemetry choice: %+v, err=%v", jobs, err)
				}
			})
		}
	}
}

func TestTelemetryFixedGroupsCaptureInvocationOptOut(t *testing.T) {
	options := testOptions(t)
	options.StandaloneGroups = true
	registry, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	job, _, key := kindFixture(t, KindGroup)
	job.ID = JobKey(job.Server, "group", job.GroupMember.GroupId+":"+job.GroupInstance)
	ctx := t.Context()
	job.TelemetryDisabled = true
	if err := registry.ReplaceGroups(ctx, []GroupInstall{{Job: job, Private: key}}); err != nil {
		t.Fatal(err)
	}
	jobs, err := registry.List(t.Context())
	if err != nil || len(jobs) != 1 || !jobs[0].TelemetryDisabled {
		t.Fatalf("fixed group lost invocation choice: %+v, err=%v", jobs, err)
	}
}
