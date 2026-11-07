package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/failure"
)

func sdkWorkloadFixture(t *testing.T, provider string, acquisition workloadmanifest.Acquisition) (*sdkFixture, func(workloadmanifest.Workload)) {
	t.Helper()
	f := newSDKFixture(t, true)
	f.operations.resolve = ResolveContext
	dir := filepath.Join(f.options.Directory, ".tnl", "generated")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f.options.Manifest = filepath.Join(dir, workloadmanifest.Filename)
	write := func(w workloadmanifest.Workload) {
		t.Helper()
		m := workloadmanifest.Manifest{Schema: 1, Server: "https://control.example", Team: "team", ProjectKey: "project", ProjectLabel: "app", SourceFingerprint: strings.Repeat("a", 64), Services: map[string]string{"db": "postgres"}, Workloads: map[string]workloadmanifest.Workload{"job": w}}
		data, _ := json.Marshal(m)
		if err := os.WriteFile(f.options.Manifest, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(workloadmanifest.Workload{Provider: provider, Services: []string{"db"}, MaxDurationSeconds: 3600, Acquisition: acquisition})
	return f, write
}

func TestConnectionSDKNativeWorkloadCurrentEnvironmentAndRecoveryFence(t *testing.T) {
	f, write := sdkWorkloadFixture(t, "vercel", workloadmanifest.Acquisition{Method: "vercel-oidc"})
	request := connectorruntime.SDKWorkloadRequest{Runtime: workloadmanifest.Runtime{Vercel: "1"}}
	data, _ := json.Marshal(map[string]any{"schema": 1, "sdk_workload": request})
	preview, err := SelectSDKWorkload(f.options.Directory, "db", bytes.NewReader(data))
	if err != nil || preview.Source != "vercel" || preview.Name != "job" || f.identified != 0 || f.started != 0 {
		t.Fatal("preview acquired or selected an owner", preview, err)
	}
	t.Setenv("VERCEL_OIDC_TOKEN", "stale.owner.environment")
	prepare := func(environment connectorruntime.SDKEnvironment, recover string) (connectorruntime.SDKPrepared, error) {
		options := f.options
		options.RecoverHandle = recover
		data, _ := json.Marshal(map[string]any{"schema": 1, "sdk_workload": request, "sdk_workload_policy": preview.Policy, "sdk_environment": environment})
		return f.operations.prepareSDK(t.Context(), options, bytes.NewReader(data))
	}
	first, err := prepare(connectorruntime.SDKEnvironment{VercelToken: "first"}, "")
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		warm, err := prepare(connectorruntime.SDKEnvironment{VercelToken: "first"}, "")
		if err != nil || warm.Owner.ConnectionHandle != first.Owner.ConnectionHandle || !warm.Owner.ExpiresAt.Equal(first.Owner.ExpiresAt) {
			t.Fatal("warm native acquisition changed owner", err)
		}
	}
	other, err := prepare(connectorruntime.SDKEnvironment{VercelToken: "other"}, "")
	if err != nil || other.Owner.ConnectionHandle == first.Owner.ConnectionHandle {
		t.Fatal("current request environment was ignored", err)
	}
	again, err := prepare(connectorruntime.SDKEnvironment{VercelToken: "first"}, "")
	if err != nil || again.Owner.ConnectionHandle != first.Owner.ConnectionHandle || f.identified != 2 || f.started != 2 {
		t.Fatal("A/B/A native selection changed its budget", err, f.identified, f.started)
	}
	if _, err := prepare(connectorruntime.SDKEnvironment{}, ""); Reason(err) != failure.WorkloadAssertionUnavailable {
		t.Fatal("fell back to stale owner environment", err)
	}
	if _, err := prepare(connectorruntime.SDKEnvironment{}, first.Owner.ConnectionHandle); Reason(err) != failure.ConnectionUnavailable {
		t.Fatal("live recovery crossed provider boundary", err)
	}
	write(workloadmanifest.Workload{Provider: "vercel", Services: []string{"db"}, MaxDurationSeconds: 1800, Acquisition: workloadmanifest.Acquisition{Method: "vercel-oidc"}})
	if _, err := prepare(connectorruntime.SDKEnvironment{VercelToken: "other"}, ""); !errors.Is(err, workloadmanifest.ErrInvalid) {
		t.Fatal("changed preview policy was accepted", err)
	}
	data, err = os.ReadFile(filepath.Join(f.options.Registry, "registry.json"))
	if err != nil || bytes.Contains(data, []byte("first")) || bytes.Contains(data, []byte("other")) || bytes.Contains(data, []byte("sdk_environment")) {
		t.Fatal("registry retained request-private provider input", err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", connectorruntime.SDKEnvironment{VercelToken: "private-secret"}, connectorruntime.SDKEnvironment{GitHubRequestToken: "private-secret"}), "private-secret") {
		t.Fatal("provider input leaked through diagnostics")
	}
}

func TestConnectionSDKWorkloadSourcesAndTokenFileRotation(t *testing.T) {
	f, _ := sdkWorkloadFixture(t, "github", workloadmanifest.Acquisition{Method: "github-actions", Audience: "https://control.example"})
	request := connectorruntime.SDKWorkloadRequest{Name: "job", TokenFile: "current.jwt"}
	selected, source, err := selectSDKWorkload(f.options.Directory, "db", request)
	if err != nil || source != "native" {
		t.Fatal(err)
	}
	file := filepath.Join(f.options.Directory, "current.jwt")
	acquire := func() (string, error) {
		return acquireSDKWorkload(context.Background(), selected, source, request, connectorruntime.SDKEnvironment{}, "")
	}
	if _, err := acquire(); !errors.Is(err, workload.ErrAssertionUnavailable) {
		t.Fatal("missing selected file fell back", err)
	}
	for _, token := range []string{"first", "rotated"} {
		if err := os.WriteFile(file, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		if actual, err := acquire(); err != nil || actual != token {
			t.Fatal("selected file was cached", err)
		}
	}
	request.Callback = true
	if _, _, err := selectSDKWorkload(f.options.Directory, "db", request); !errors.Is(err, workloadmanifest.ErrRequired) {
		t.Fatal("two explicit sources accepted", err)
	}
	request.TokenFile = ""
	if _, source, err := selectSDKWorkload(f.options.Directory, "db", request); err != nil || source != "callback" {
		t.Fatal("explicit GitHub callback rejected", err)
	}
	request.Callback = false
	if _, _, err := selectSDKWorkload(f.options.Directory, "db", request); !errors.Is(err, workloadmanifest.ErrRequired) {
		t.Fatal("missing explicit source accepted", err)
	}
}

func TestConnectionSDKWorkloadEnvironmentOverride(t *testing.T) {
	f, _ := sdkWorkloadFixture(t, "oidc", workloadmanifest.Acquisition{Method: "token-env", Audience: "https://control.example", TokenEnv: "JOB_ID_TOKEN"})
	request := connectorruntime.SDKWorkloadRequest{Runtime: workloadmanifest.Runtime{Workload: new("job")}}
	data, _ := json.Marshal(map[string]any{"schema": 1, "sdk_workload": request})
	preview, err := SelectSDKWorkload(f.options.Directory, "db", bytes.NewReader(data))
	if err != nil || preview.Source != "native" || preview.TokenEnv != "JOB_ID_TOKEN" || f.identified != 0 || f.started != 0 {
		t.Fatal("environment selection acquired provider identity", err)
	}
	t.Setenv("JOB_ID_TOKEN", "stale.owner.value")
	prepare := func(token string) (connectorruntime.SDKPrepared, error) {
		environment := connectorruntime.SDKEnvironment{TokenEnv: "JOB_ID_TOKEN", TokenValue: token}
		input, _ := json.Marshal(map[string]any{"schema": 1, "sdk_workload": request, "sdk_workload_policy": preview.Policy, "sdk_environment": environment})
		return f.operations.prepareSDK(t.Context(), f.options, bytes.NewReader(input))
	}
	first, err := prepare("first")
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		warm, err := prepare("first")
		if err != nil || warm.Owner.ConnectionHandle != first.Owner.ConnectionHandle {
			t.Fatal("environment acquisition replaced warm owner", err)
		}
	}
	other, err := prepare("other")
	if err != nil || other.Owner.ConnectionHandle == first.Owner.ConnectionHandle {
		t.Fatal("changed environment reused another identity", err)
	}
	if _, err := prepare(""); Reason(err) != failure.WorkloadAssertionUnavailable {
		t.Fatal("empty environment fell back to owner process", err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", connectorruntime.SDKEnvironment{TokenEnv: "JOB_ID_TOKEN", TokenValue: "private-value"}, connectorruntime.SDKEnvironment{TokenValue: "private-value"}), "private-value") {
		t.Fatal("environment input leaked")
	}
}

func TestConnectionSDKRefreshKeepsSelectedSource(t *testing.T) {
	directory := t.TempDir()
	for _, test := range []struct {
		name, source, assertion string
		hints                   workloadmanifest.Acquisition
		request                 connectorruntime.SDKWorkloadRequest
		environment             connectorruntime.SDKEnvironment
		want                    *workloadmanifest.Acquisition
	}{
		{name: "callback does not borrow a file", source: "callback", assertion: "private.jwt", hints: workloadmanifest.Acquisition{Method: "github-actions"}, environment: connectorruntime.SDKEnvironment{VercelTokenFile: "fallback.jwt"}},
		{name: "Vercel request token does not borrow a file", source: "vercel", assertion: "private.jwt", hints: workloadmanifest.Acquisition{Method: "vercel-oidc"}, environment: connectorruntime.SDKEnvironment{VercelTokenFile: "fallback.jwt"}},
		{name: "selected Vercel file", source: "vercel", hints: workloadmanifest.Acquisition{Method: "vercel-oidc"}, environment: connectorruntime.SDKEnvironment{VercelTokenFile: "current.jwt"}, want: &workloadmanifest.Acquisition{Method: "token-file", TokenFile: filepath.Join(directory, "current.jwt")}},
		{name: "explicit runtime file", source: "native", hints: workloadmanifest.Acquisition{Method: "github-actions"}, request: connectorruntime.SDKWorkloadRequest{TokenFile: "current.jwt"}, want: &workloadmanifest.Acquisition{Method: "token-file", TokenFile: filepath.Join(directory, "current.jwt")}},
		{name: "declared file", source: "native", hints: workloadmanifest.Acquisition{Method: "token-file", TokenFile: "current.jwt"}, want: &workloadmanifest.Acquisition{Method: "token-file", TokenFile: filepath.Join(directory, "current.jwt")}},
		{name: "static selected environment", source: "native", hints: workloadmanifest.Acquisition{Method: "token-env", TokenEnv: "JWT"}, environment: connectorruntime.SDKEnvironment{TokenEnv: "JWT", TokenValue: "private.jwt"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := workloadmanifest.Selection{Directory: directory, Workload: workloadmanifest.Workload{Acquisition: test.hints}}
			got := sdkWorkloadRefresh(selected, test.source, test.request, test.environment, test.assertion)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatal("refresh changed the selected acquisition source")
			}
		})
	}
}

func TestConnectionSDKStartupTransfersOnlyNativeRefreshHints(t *testing.T) {
	f, _ := sdkWorkloadFixture(t, "github", workloadmanifest.Acquisition{Method: "github-actions", Audience: "https://control.example"})
	file := filepath.Join(f.options.Directory, "current.jwt")
	if err := os.WriteFile(file, []byte("private-startup-assertion"), 0600); err != nil {
		t.Fatal(err)
	}
	request := connectorruntime.SDKWorkloadRequest{Name: "job", TokenFile: "current.jwt"}
	selected, _, err := selectSDKWorkload(f.options.Directory, "db", request)
	if err != nil {
		t.Fatal(err)
	}
	start := f.operations.start
	f.operations.start = func(ctx context.Context, options OwnerStartOptions, request connectorruntime.StartRequest, accept func(connectorruntime.Status) error) error {
		if request.Refresh == nil || request.Refresh.Method != "token-file" || request.Refresh.TokenFile != file || request.Refresh.TokenEnv != "" || request.Assertion != "private-startup-assertion" {
			t.Fatal("startup lost the selected refresh source")
		}
		return start(ctx, options, request, accept)
	}
	input, _ := json.Marshal(map[string]any{"schema": 1, "sdk_workload": request, "sdk_workload_policy": selected.Policy})
	if _, err := f.operations.prepareSDK(t.Context(), f.options, bytes.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(f.options.Registry, "registry.json"))
	if err != nil || bytes.Contains(data, []byte(file)) || bytes.Contains(data, []byte("private-startup-assertion")) || bytes.Contains(data, []byte(`"refresh"`)) {
		t.Fatal("registry persisted private startup or refresh acquisition state", err)
	}
}
