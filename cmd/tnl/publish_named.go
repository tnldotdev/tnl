package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/dockertarget"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

type namedPublisherClient struct {
	endpoint localPublisherEndpoint
	http     *http.Client
}

var errNamedPublisherUnauthenticated = localpublisher.ErrUnauthenticated
var errNamedPublisherLost = localpublisher.ErrLost

func namedPublisherConnectionLost(err error) bool {
	var network *url.Error
	return errors.As(err, &network) || errors.Is(err, errNamedPublisherUnauthenticated) || errors.Is(err, errNamedPublisherLost)
}

func namedPublishOverrides(parsed *kong.Context) []string {
	var unsupported []string
	for _, flag := range parsed.Flags() {
		if flag.Name == "inspection-mode" && fmt.Sprint(parsed.FlagValue(flag)) == "summary" {
			continue
		}
		if !flag.Set || !slices.Contains([]string{
			"server", "access-token", "team", "domain", "name", "public-url", "allow-ip", "allow-all-ips",
			"ephemeral", "total", "rate-count", "rate-per", "rate-burst", "concurrency", "protocol", "target-ca-file",
			"traffic-connections", "traffic-rate-count", "traffic-rate-per", "traffic-rate-burst", "traffic-upload", "traffic-download",
			"target-tls-name", "target-tls", "inspection-mode",
			"inspection-retention", "inspection-max-bytes",
		}, flag.Name) {
			continue
		}
		unsupported = append(unsupported, "--"+flag.Name)
	}
	slices.Sort(unsupported)
	return unsupported
}

func (c namedPublisherClient) request(ctx context.Context, method, path, owner string, body any, value any) error {
	return localpublisher.Request(ctx, c.http, c.endpoint, method, path, owner, body, value)
}

func localPublisherForCLI(ctx context.Context, flags publishCommand) (namedPublisherClient, func(), error) {
	if selection := flags.project.Config.Publisher; selection != nil && selection.Type != "local" {
		if selection.Type == "docker" {
			if err := validateDockerPublisherTarget(ctx, flags.project, flags.Service); err != nil {
				return namedPublisherClient{}, nil, err
			}
		}
		client, err := selectedPublisherClient(ctx, flags.project, 10*time.Second)
		if err != nil {
			return namedPublisherClient{}, nil, err
		}
		var snapshot localpublisherv1.ProjectSnapshot
		if err := client.request(ctx, http.MethodGet, "/v1/status", "", nil, &snapshot); err != nil {
			return namedPublisherClient{}, nil, err
		}
		if snapshot.Project != flags.projectRoot {
			return namedPublisherClient{}, nil, failure.Wrap("select project publisher", failure.ProjectConfigInvalid,
				errors.New("publisher project directory differs; mount the worktree at the same path as the host"))
		}
		return client, func() {}, nil
	}
	options := runtimeOptions{Directory: flags.projectRoot, StateDir: flags.StateDir}
	project, root, err := runtimeProject(ctx, options)
	if err != nil {
		return namedPublisherClient{}, nil, err
	}
	key, err := runtimeKey(project.Root, root)
	if err != nil {
		return namedPublisherClient{}, nil, err
	}
	workerCtx, stop := context.WithCancel(ctx)
	if !runtimeAvailable(ctx, key) {
		go func() { _ = runRuntimeServe(workerCtx, options) }()
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		for !runtimeAvailable(ctx, key) {
			select {
			case <-ctx.Done():
				stop()
				return namedPublisherClient{}, nil, ctx.Err()
			case <-deadline.C:
				stop()
				return namedPublisherClient{}, nil, diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("local publisher did not start; check the project configuration and sign-in"))
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		stop()
		return namedPublisherClient{}, nil, err
	}
	return namedPublisherClient{endpoint: endpoint, http: &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}}, stop, nil
}

func validateDockerPublisherTarget(ctx context.Context, project projectConfiguration, name string) error {
	if name == "" {
		return nil
	}
	service := project.Config.Services[name]
	if service.Target == nil || service.Target.Type != "docker" {
		return nil
	}
	owner := project.Config.Publisher
	if owner == nil || owner.Type != "docker" || service.Target.Compose == nil || owner.Compose == nil ||
		owner.Compose.File != service.Target.Compose.File || owner.Compose.Project != service.Target.Compose.Project {
		return failure.Wrap("select Docker publisher target", failure.ProjectConfigInvalid,
			errors.New("the target and publisher must be services in the same Compose file and worktree"))
	}
	publisher, err := dockertarget.SelectContainer(ctx, project.Root, project.Worktree.Label.FullLabel, owner.DockerSelection)
	if err != nil {
		return failure.Wrap("select Docker publisher", failure.ClientStateUnavailable, err)
	}
	target, err := dockertarget.SelectContainer(ctx, project.Root, project.Worktree.Label.FullLabel, service.Target.DockerSelection)
	if err != nil {
		return failure.Wrap("select Docker target", failure.ClientStateUnavailable, err)
	}
	for _, network := range target.Networks {
		if slices.Contains(publisher.Networks, network) {
			return nil
		}
	}
	return failure.Wrap("select Docker publisher target", failure.ProjectConfigInvalid,
		errors.New("the target and publisher containers have no shared Compose network"))
}

func runNamedPublish(ctx context.Context, flags publishCommand, stdout, stderr io.Writer, reporters ...telemetryReporter) (result error) {
	if slices.Contains(flags.namedOverrides, "--server") {
		configured := valueOrEmpty(flags.project.Config.Server)
		if flags.ServerURL == configured || os.Getenv("TNL_SERVER") != "" && flags.ServerURL == os.Getenv("TNL_SERVER") {
			flags.namedOverrides = slices.DeleteFunc(flags.namedOverrides, func(name string) bool { return name == "--server" })
		}
	}
	if len(flags.namedOverrides) != 0 {
		return failure.Wrap("publish configured service", failure.InvalidTunnelFlags,
			fmt.Errorf("named publications use project settings; remove %s or publish an explicit target", strings.Join(flags.namedOverrides, ", ")))
	}
	if flags.Ephemeral {
		return failure.Wrap("publish configured service", failure.InvalidTunnelFlags,
			errors.New("named service public URLs are saved; publish an explicit target for an ephemeral URL"))
	}
	output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, nil)
	if err != nil {
		return err
	}
	output.setInspectionMode(flags.InspectionMode)
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
	unauthenticated := 0
	var recoveryUntil time.Time
	for ctx.Err() == nil {
		client, stop, err := localPublisherForCLI(ctx, flags)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			reason, known := failure.ReasonOf(err)
			if recoveryUntil.IsZero() || time.Now().After(recoveryUntil) || !(known && reason == failure.ClientStateUnavailable || namedPublisherConnectionLost(err)) {
				return err
			}
			if err := waitNamedPublisherRetry(ctx); err != nil {
				return err
			}
			continue
		}
		recoveryUntil = time.Time{}
		err = followNamedPublication(ctx, flags, client, owner, output, telemetry, serverKind)
		stop()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !namedPublisherConnectionLost(err) {
			return err
		}
		recoveryUntil = time.Now().Add(30 * time.Second)
		if errors.Is(err, errNamedPublisherUnauthenticated) {
			unauthenticated++
			if unauthenticated > 1 {
				return diagnostic.Wrap(diagnostic.AuthenticationRequired, err)
			}
		}
		if err := waitNamedPublisherRetry(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func waitNamedPublisherRetry(ctx context.Context) error {
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func followNamedPublication(ctx context.Context, flags publishCommand, client namedPublisherClient, owner string, output *publishOutput, telemetry telemetryReporter, serverKind telemetryServerKind) (result error) {
	var lease localpublisherv1.PublicationLease
	if err := client.request(ctx, http.MethodPost, "/v1/publications", "", localpublisherv1.PublicationRequest{
		Service: flags.Service, Owner: owner, Pid: os.Getpid(),
	}, &lease); err != nil {
		return err
	}
	if lease.Service != flags.Service || lease.PublicationId == "" || lease.Cursor == "" {
		return failure.Wrap("start named publication", failure.ServerResponseInvalid, errors.New("local publisher returned an invalid publication lease"))
	}
	defer func() {
		if namedPublisherConnectionLost(result) {
			return
		}
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		err := client.request(closeCtx, http.MethodDelete, "/v1/publications/"+lease.PublicationId, owner, nil, nil)
		if ctx.Err() == nil && err != nil {
			result = errors.Join(result, err)
		}
	}()
	cursor := lease.Cursor
	nextRenew := time.Now().Add(clientruntime.LeaseDuration / 4)
	started := ""
	currentIPReported := false
	for ctx.Err() == nil {
		if time.Now().After(nextRenew) {
			if err := client.request(ctx, http.MethodPost, "/v1/publications/"+lease.PublicationId+"/renew", owner, nil, nil); err != nil {
				return err
			}
			nextRenew = time.Now().Add(clientruntime.LeaseDuration / 4)
		}
		var page localpublisherv1.ProjectEventPage
		if err := client.request(ctx, http.MethodGet, "/v1/events?after="+cursor+"&wait_seconds=1", "", nil, &page); err != nil {
			return err
		}
		for _, event := range page.Events {
			if event.Service == flags.Service && event.Type == "service.stopped" && started != "" {
				return errNamedPublisherLost
			}
			if event.Service != flags.Service || event.Status == nil || event.Status.PublicationId == nil || *event.Status.PublicationId != lease.PublicationId {
				continue
			}
			if event.Type == "service.failed" {
				return diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("named publication could not start; check tnl status"))
			}
			if event.Status.TunnelId != nil && *event.Status.TunnelId != started {
				started = *event.Status.TunnelId
				target := ""
				if event.Status.Target != nil {
					target = *event.Status.Target
				}
				if err := output.starting(started, target); err != nil {
					return err
				}
				if !currentIPReported && lease.CurrentIp != nil {
					currentIPReported = true
					if err := output.currentIP(*lease.CurrentIp); err != nil {
						return err
					}
				}
			}
			if event.Publication == nil {
				continue
			}
			if err := presentNamedEvent(output, *event.Publication); err != nil {
				return err
			}
			if event.Publication.Type == "ready" && telemetry != nil {
				telemetry.Report(newTelemetryReady(telemetryPublish, serverKind, ""))
				if invocation, ok := telemetry.(*telemetryInvocation); ok {
					invocation.flushReady()
				}
			}
		}
		position, err := clientruntime.ParseCursor(page.Cursor)
		previous, previousErr := clientruntime.ParseCursor(cursor)
		if err != nil || previousErr != nil || position < previous || position == previous && len(page.Events) != 0 {
			return failure.Wrap("follow named publication", failure.ServerResponseInvalid, errors.New("local publisher did not advance the event cursor"))
		}
		cursor = page.Cursor
	}
	return ctx.Err()
}

func presentNamedEvent(output *publishOutput, event localpublisherv1.PublicationEvent) error {
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
	case "ready":
		if event.PublicUrl != nil {
			return output.ready(*event.PublicUrl, number)
		}
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
