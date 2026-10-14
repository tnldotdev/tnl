package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

const maxNamedResponse = 256 << 10

var errNamedOwnerLost = errors.New("local publisher owner stopped")
var errNamedOwnerUnauthorized = errors.New("local publisher owner credential expired")

type namedPublisherClient struct {
	endpoint localPublisherEndpoint
	http     *http.Client
}

func (c namedPublisherClient) request(ctx context.Context, method, path, owner string, body, result any) error {
	var input io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		input = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.endpoint.URL+path, input)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.endpoint.Credential)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if owner != "" {
		request.Header.Set("X-Publication-Owner", owner)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxNamedResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxNamedResponse {
		return failure.Wrap("read local publisher", failure.ServerResponseInvalid, errors.New("local publisher response exceeds limit"))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var problem localpublisherv1.Problem
		if json.Unmarshal(data, &problem) != nil || problem.Code == "" {
			return failure.Wrap("read local publisher", failure.ServerResponseInvalid, errors.New("local publisher returned an invalid problem"))
		}
		if response.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("%w: %s", errNamedOwnerUnauthorized, problem.Message)
		}
		if response.StatusCode == http.StatusGone || problem.Code == "runtime.registration_stale" {
			return fmt.Errorf("%w: %s", errNamedOwnerLost, problem.Message)
		}
		return fmt.Errorf("%s: %s", problem.Code, problem.Message)
	}
	if result == nil {
		if response.StatusCode != http.StatusNoContent || len(data) != 0 {
			return failure.Wrap("read local publisher", failure.ServerResponseInvalid, errors.New("unexpected local publisher response"))
		}
		return nil
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" || json.Unmarshal(data, result) != nil {
		return failure.Wrap("read local publisher", failure.ServerResponseInvalid, errors.New("invalid local publisher JSON"))
	}
	return nil
}

func localPublisherForCLI(ctx context.Context, flags publishCommand) (namedPublisherClient, func(), error) {
	options := runtimeOptions{Directory: flags.projectRoot, StateDir: flags.StateDir, Embedded: true}
	project, state, err := runtimeProject(ctx, options)
	if err != nil {
		return namedPublisherClient{}, nil, err
	}
	key, err := runtimeKey(project.Root, state)
	if err != nil {
		return namedPublisherClient{}, nil, err
	}
	workerCtx, stop := context.WithCancel(ctx)
	var workerDone <-chan struct{}
	finish := func() {
		stop()
		if workerDone != nil {
			select {
			case <-workerDone:
			case <-time.After(5 * time.Second):
			}
		}
	}
	if !runtimeAvailable(ctx, key) {
		done := make(chan struct{})
		workerDone = done
		go func() { defer close(done); _ = runRuntimeServe(workerCtx, options) }()
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		for !runtimeAvailable(ctx, key) {
			select {
			case <-ctx.Done():
				finish()
				return namedPublisherClient{}, nil, ctx.Err()
			case <-deadline.C:
				finish()
				return namedPublisherClient{}, nil, diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("local publisher did not start; check project configuration and sign-in"))
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		finish()
		return namedPublisherClient{}, nil, err
	}
	return namedPublisherClient{endpoint: endpoint, http: &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}}, finish, nil
}

func namedConnectionLost(err error) bool {
	var network *url.Error
	return errors.As(err, &network) || errors.Is(err, errNamedOwnerLost) || errors.Is(err, errNamedOwnerUnauthorized)
}

func runNamedPublish(ctx context.Context, flags publishCommand, stdout, stderr io.Writer, reporters ...telemetryReporter) (result error) {
	selectedServer := valueOrEmpty(flags.project.Config.Server)
	if environment := os.Getenv("TNL_SERVER"); environment != "" {
		selectedServer = environment
	}
	if slices.Contains(flags.namedOverrides, "--server") && selectedServer != "" && flags.ServerURL == selectedServer {
		flags.namedOverrides = slices.DeleteFunc(flags.namedOverrides, func(flag string) bool { return flag == "--server" })
	}
	if len(flags.namedOverrides) != 0 {
		return failure.Wrap("publish configured service", failure.InvalidTunnelFlags,
			fmt.Errorf("named publications use project settings; remove %s or publish an explicit target", strings.Join(flags.namedOverrides, ", ")))
	}
	if flags.Ephemeral {
		return failure.Wrap("publish configured service", failure.InvalidTunnelFlags, errors.New("named public URLs are saved; publish an explicit target for an ephemeral URL"))
	}
	output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, nil)
	if err != nil {
		return err
	}
	if flags.Protocol == "" || flags.Protocol == "http" {
		output.openURL = browserOpener(ctx, flags.Open, false)
	}
	defer func() { result = output.finish(ctx, result) }()
	ownerBytes := make([]byte, 16)
	if _, err := rand.Read(ownerBytes); err != nil {
		return err
	}
	owner := hex.EncodeToString(ownerBytes)
	telemetry := optionalTelemetryReporter(reporters)
	server := flags.ServerURL
	if server == "" {
		server = valueOrEmpty(flags.project.Config.Server)
	}
	serverKind := telemetrySelfHosted
	if server == defaultServerURL {
		serverKind = telemetryHosted
	}
	unauthorized := 0
	for ctx.Err() == nil {
		client, stop, err := localPublisherForCLI(ctx, flags)
		if err != nil {
			return err
		}
		err = followNamedPublication(ctx, flags, client, owner, output, telemetry, serverKind)
		stop()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !namedConnectionLost(err) {
			return err
		}
		if errors.Is(err, errNamedOwnerUnauthorized) {
			unauthorized++
			if unauthorized > 1 {
				return diagnostic.Wrap(diagnostic.AuthenticationRequired, err)
			}
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return ctx.Err()
}

func followNamedPublication(ctx context.Context, flags publishCommand, client namedPublisherClient, owner string, output *publishOutput, telemetry telemetryReporter, serverKind telemetryServerKind) (result error) {
	var lease localpublisherv1.PublicationLease
	if err := client.request(ctx, http.MethodPost, "/v1/publications", "", localpublisherv1.PublicationRequest{
		Service: flags.Service, Owner: owner, Pid: os.Getpid(),
	}, &lease); err != nil {
		return err
	}
	if lease.Service != flags.Service || lease.PublicationId == "" {
		return failure.Wrap("start named publication", failure.ServerResponseInvalid, errors.New("local publisher returned an invalid lease"))
	}
	if _, err := clientruntime.ParseCursor(lease.Cursor); err != nil {
		return failure.Wrap("start named publication", failure.ServerResponseInvalid, err)
	}
	defer func() {
		if namedConnectionLost(result) {
			return
		}
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		err := client.request(closeCtx, http.MethodDelete, "/v1/publications/"+lease.PublicationId, owner, nil, nil)
		if ctx.Err() == nil && err != nil {
			result = errors.Join(result, err)
		}
	}()
	cursor, started, readyRun := lease.Cursor, output.tunnelID, output.readyPublishRunNumber
	present := func(status *localpublisherv1.ServiceStatus) error {
		if status == nil || status.PublicationId == nil || *status.PublicationId != lease.PublicationId {
			return nil
		}
		if status.TunnelId != nil && *status.TunnelId != started {
			started = *status.TunnelId
			target := ""
			if status.Target != nil {
				target = *status.Target
			}
			if err := output.starting(started, target); err != nil {
				return err
			}
			if lease.CurrentIp != nil {
				if err := output.currentIP(*lease.CurrentIp); err != nil {
					return err
				}
			}
		}
		if (status.State == localpublisherv1.ServiceStatusStateRoutable || status.State == localpublisherv1.ServiceStatusStateReady) && status.PublishRunNumber != nil && uint64(*status.PublishRunNumber) != readyRun {
			readyRun = uint64(*status.PublishRunNumber)
			if status.PublicUrl != nil {
				if err := output.ready(*status.PublicUrl, readyRun); err != nil {
					return err
				}
			}
			if telemetry != nil {
				telemetry.Report(newTelemetryReady(telemetryPublish, serverKind, ""))
				if invocation, ok := telemetry.(*telemetryInvocation); ok {
					invocation.flushReady()
				}
			}
		}
		return nil
	}
	var snapshot localpublisherv1.ProjectSnapshot
	if err := client.request(ctx, http.MethodGet, "/v1/status", "", nil, &snapshot); err != nil {
		return err
	}
	for i := range snapshot.Services {
		if snapshot.Services[i].Service == flags.Service {
			if err := present(&snapshot.Services[i]); err != nil {
				return err
			}
		}
	}
	nextRenew := time.Now().Add(clientruntime.LeaseDuration / 4)
	for ctx.Err() == nil {
		if time.Now().After(nextRenew) {
			if err := client.request(ctx, http.MethodPost, "/v1/publications/"+lease.PublicationId+"/renew", owner, nil, nil); err != nil {
				return err
			}
			nextRenew = time.Now().Add(clientruntime.LeaseDuration / 4)
		}
		var page localpublisherv1.ProjectEventPage
		if err := client.request(ctx, http.MethodGet, "/v1/events?after="+url.QueryEscape(cursor)+"&wait_seconds=1", "", nil, &page); err != nil {
			return err
		}
		for _, event := range page.Events {
			if event.Service == nil || *event.Service != flags.Service || event.Status == nil || event.Status.PublicationId == nil || *event.Status.PublicationId != lease.PublicationId {
				continue
			}
			status := event.Status
			if event.Type == "service.failed" {
				return diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("named publication failed; check tnl status"))
			}
			if event.Publication != nil {
				if event.Publication.Type != "provisioning" || event.Publication.PublishRunNumber == nil || uint64(*event.Publication.PublishRunNumber) > readyRun {
					if err := presentNamedProgress(output, *event.Publication); err != nil {
						return err
					}
				}
			}
			if err := present(status); err != nil {
				return err
			}
		}
		position, err := clientruntime.ParseCursor(page.Cursor)
		previous, beforeErr := clientruntime.ParseCursor(cursor)
		if err != nil || beforeErr != nil || position < previous || position == previous && len(page.Events) != 0 {
			return failure.Wrap("follow named publication", failure.ServerResponseInvalid, errors.New("local publisher did not advance the event cursor"))
		}
		cursor = page.Cursor
	}
	return ctx.Err()
}

func presentNamedProgress(output *publishOutput, event localpublisherv1.PublicationEvent) error {
	number := uint64(0)
	if event.PublishRunNumber != nil && *event.PublishRunNumber > 0 {
		number = uint64(*event.PublishRunNumber)
	}
	switch event.Type {
	case "provisioning":
		if event.Hostname != nil {
			return output.provisioning(*event.Hostname, number)
		}
	case "provisioning_stalled":
		return output.provisioningStalled(number)
	case "transport_fallback":
		if event.Transport != nil {
			return output.transportFallback(number, string(*event.Transport))
		}
	case "ip_policy_denials":
		if event.PolicyDenials != nil {
			return output.blockedVisitors(number, uint64(*event.PolicyDenials))
		}
	case "target_unavailable":
		return output.targetUnavailable()
	case "cancel_unsupported":
		return output.cancelUnsupported(number)
	}
	return nil
}
