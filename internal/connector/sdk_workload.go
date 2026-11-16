package connector

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/failure"
)

// SelectSDKWorkload resolves acquisition without provider/control calls or owner
// startup. the same operation serves the first CLI request and warm local IPC.
func SelectSDKWorkload(directory, service string, input io.Reader) (connectorruntime.SDKWorkload, error) {
	var request struct {
		Schema   int                                 `json:"schema"`
		Workload connectorruntime.SDKWorkloadRequest `json:"sdk_workload"`
	}
	if connectorruntime.ReadJSON(input, &request) != nil || request.Schema != 1 {
		return connectorruntime.SDKWorkload{}, connectorruntime.ErrInvalid
	}
	selected, source, err := selectSDKWorkload(directory, service, request.Workload)
	return sdkWorkloadContext(selected, source), err
}

func selectSDKWorkload(directory, service string, request connectorruntime.SDKWorkloadRequest) (workloadmanifest.Selection, string, error) {
	selected, err := workloadmanifest.Select(directory, request.Name, service, request.Runtime)
	if err != nil {
		return selected, "", err
	}
	scope := connectorruntime.Context{TeamID: selected.Manifest.Team, TeamName: selected.Manifest.Team, ProjectKey: selected.Manifest.ProjectKey, Deployment: selected.Workload.Deployment}
	if !scope.MatchesSelection(request.Selection) {
		return selected, "", connectorruntime.ErrUnauthorized
	}
	if request.Name == "" && (request.Callback || request.TokenFile != "") || request.Name != "" && request.Callback == (request.TokenFile != "") {
		return selected, "", workloadmanifest.ErrRequired
	}
	method := selected.Workload.Acquisition.Method
	if request.Name != "" {
		if method != "callback" && method != "github-actions" {
			return selected, "", workload.ErrAssertionSource
		}
		if request.Callback {
			return selected, "callback", nil
		}
		if len(request.TokenFile) > 4096 || strings.ContainsRune(request.TokenFile, 0) {
			return selected, "", workload.ErrAssertionSource
		}
		return selected, "native", nil
	}
	switch method {
	case "vercel-oidc":
		return selected, "vercel", nil
	case "callback":
		return selected, "callback", nil
	default:
		return selected, "native", nil
	}
}

func sdkWorkloadContext(selected workloadmanifest.Selection, source string) connectorruntime.SDKWorkload {
	return connectorruntime.SDKWorkload{Schema: 1, Name: selected.Name, Directory: selected.Directory, Manifest: selected.Path, Policy: selected.Policy, Source: source, TokenEnv: selected.Workload.Acquisition.TokenEnv}
}

func sdkWorkloadRefresh(selected workloadmanifest.Selection, source string, request connectorruntime.SDKWorkloadRequest, environment connectorruntime.SDKEnvironment, assertion string) *workloadmanifest.Acquisition {
	if source == "callback" || source == "vercel" && assertion != "" {
		return nil
	}
	hints := selected.Workload.Acquisition
	if request.TokenFile != "" {
		hints = workloadmanifest.Acquisition{Method: "token-file", TokenFile: request.TokenFile}
	}
	return workload.RefreshSource(selected.Directory, hints, environment.Getenv)
}

func acquireSDKWorkload(ctx context.Context, selected workloadmanifest.Selection, source string, request connectorruntime.SDKWorkloadRequest, environment connectorruntime.SDKEnvironment, assertion string) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if source == "callback" || source == "vercel" && assertion != "" {
		return (workload.AssertionSource{Assertion: assertion}).Acquire(bounded)
	}
	if assertion != "" {
		return "", workload.ErrAssertionSource
	}
	if request.TokenFile != "" {
		file := request.TokenFile
		if !filepath.IsAbs(file) {
			file = filepath.Join(selected.Directory, file)
		}
		return (workload.AssertionSource{TokenFile: file}).Acquire(bounded)
	}
	hints := selected.Workload.Acquisition
	if hints.Method == "vercel-oidc" && environment.VercelTokenFile != "" && !filepath.IsAbs(environment.VercelTokenFile) {
		environment.VercelTokenFile = filepath.Join(selected.Directory, environment.VercelTokenFile)
	}
	if hints.TokenFile != "" && !filepath.IsAbs(hints.TokenFile) {
		hints.TokenFile = filepath.Join(selected.Directory, hints.TokenFile)
	}
	return workload.Acquire(bounded, hints, nil, environment.Getenv)
}

func (b *connectorConnectionBackend) SDKWorkload(ctx context.Context, request connectorruntime.Request) (connectorruntime.SDKWorkload, error) {
	if b.sdk == nil || request.SDKWorkload == nil {
		return connectorruntime.SDKWorkload{}, connectorruntime.ErrInvalid
	}
	_, finish, err := b.begin(ctx)
	if err != nil {
		return connectorruntime.SDKWorkload{}, err
	}
	defer finish()
	selected, source, err := selectSDKWorkload(b.scope.Directory, request.Service, *request.SDKWorkload)
	if err != nil {
		err = failure.Wrap("select SDK workload", Reason(err), err)
	}
	return sdkWorkloadContext(selected, source), err
}
