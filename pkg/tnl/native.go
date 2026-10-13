package tnl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
)

type nativeRuntime struct {
	directory, stateDir, binary, endpointFile string
	http                                      *http.Client
}

func newNativeRuntime(options Options) (nativeRuntime, error) {
	directory := options.Directory
	if directory == "" {
		var err error
		directory, err = os.Getwd()
		if err != nil {
			return nativeRuntime{}, err
		}
	}
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nativeRuntime{}, err
	}
	selected := options.PublisherEndpointFile
	if selected == "" {
		selected = os.Getenv("TNL_PUBLISHER_ENDPOINT_FILE")
	}
	return nativeRuntime{directory: directory, stateDir: options.StateDir,
		binary: options.PublisherBinary, endpointFile: selected, http: localpublisher.HTTPClient(5 * time.Second)}, nil
}

func (n nativeRuntime) args(command string) []string {
	result := []string{"runtime", command, "--directory", n.directory}
	if n.stateDir != "" {
		result = append(result, "--state-dir", n.stateDir)
	}
	if command == "endpoint" {
		result = append(result, "--ad-hoc")
	}
	return result
}

func (n nativeRuntime) endpoint(ctx context.Context) (localpublisher.Endpoint, error) {
	if n.endpointFile != "" {
		return n.available(ctx, n.endpointFile)
	}
	binary := n.binary
	if binary == "" {
		var err error
		binary, err = exec.LookPath("tnl")
		if err != nil {
			return localpublisher.Endpoint{}, fmt.Errorf("find the tnl publisher binary: %w", err)
		}
	}
	requestCtx, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	command := exec.CommandContext(requestCtx, binary, n.args("endpoint")...)
	output, err := command.Output()
	if err != nil || len(output) > 64<<10 {
		return localpublisher.Endpoint{}, errors.New("tnl could not locate the project publisher")
	}
	var descriptor struct {
		Version int    `json:"version"`
		Path    string `json:"path"`
		Spawn   bool   `json:"spawn"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&descriptor) != nil || decoder.Decode(new(any)) != io.EOF ||
		descriptor.Version != privateprotocol.Version || !filepath.IsAbs(descriptor.Path) ||
		!strings.HasSuffix(descriptor.Path, ".endpoint.json") {
		return localpublisher.Endpoint{}, errors.New("tnl returned an invalid publisher endpoint")
	}
	if endpoint, err := n.available(ctx, descriptor.Path); err == nil {
		return endpoint, nil
	}
	if !descriptor.Spawn {
		return localpublisher.Endpoint{}, errors.New("the selected publisher is not running")
	}
	worker := exec.Command(binary, n.args("serve")...)
	worker.Dir, worker.Stdout, worker.Stderr = n.directory, io.Discard, io.Discard
	if err := worker.Start(); err != nil {
		return localpublisher.Endpoint{}, fmt.Errorf("start the project publisher: %w", err)
	}
	_ = worker.Process.Release()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		if endpoint, err := n.available(ctx, descriptor.Path); err == nil {
			return endpoint, nil
		}
		select {
		case <-ctx.Done():
			return localpublisher.Endpoint{}, context.Cause(ctx)
		case <-deadline.C:
			return localpublisher.Endpoint{}, errors.New("the project publisher did not become ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (n nativeRuntime) available(ctx context.Context, path string) (localpublisher.Endpoint, error) {
	endpoint, err := localpublisher.ReadDescriptor(path)
	if err != nil {
		return localpublisher.Endpoint{}, err
	}
	var status struct{}
	if err := localpublisher.Request(ctx, n.http, endpoint, http.MethodGet, "/v1/status", "", nil, &status); err != nil {
		return localpublisher.Endpoint{}, err
	}
	return endpoint, nil
}

func (n nativeRuntime) call(ctx context.Context, endpoint localpublisher.Endpoint, action string, body any, status *privateprotocol.AdHocStatus) error {
	method, path := http.MethodPost, "/v1/ad-hoc/"+action
	var output any
	if status != nil {
		output = status
	}
	return localpublisher.Request(ctx, n.http, endpoint, method, path, "", body, output)
}

func (n nativeRuntime) follow(ctx context.Context, register privateprotocol.AdHocRegister, ready func(privateprotocol.AdHocStatus)) error {
	registration := privateprotocol.Registration{Version: privateprotocol.Version,
		RegistrationID: register.RegistrationID, Owner: register.Owner}
	var current localpublisher.Endpoint
	defer func() {
		if current.URL != "" {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = n.call(cleanupCtx, current, "unregister", registration, nil)
		}
	}()
	lastReady := uint64(0)
	for ctx.Err() == nil {
		endpoint, err := n.endpoint(ctx)
		if err != nil {
			return err
		}
		current = endpoint
		status := privateprotocol.AdHocStatus{}
		if err := n.call(ctx, endpoint, "register", register, &status); err != nil {
			return err
		}
		ticker := time.NewTicker(500 * time.Millisecond)
		renew := time.NewTicker(clientruntime.LeaseDuration / 3)
		lost := false
		for !lost {
			if status.Version != privateprotocol.Version || status.RegistrationID != register.RegistrationID || !status.State.Valid() {
				return errors.New("tnl returned an invalid ad-hoc registration")
			}
			switch status.State {
			case privateprotocol.AdHocRoutable:
				if status.PublicURLID == "" || status.PublicURL == "" || status.PublishRunNumber == 0 {
					return errors.New("tnl returned an incomplete public URL")
				}
				if status.PublishRunNumber != lastReady {
					lastReady = status.PublishRunNumber
					ready(status)
				}
			case privateprotocol.AdHocFailed:
				return fmt.Errorf("tnl could not publish the app: %s", status.FailureCode)
			case privateprotocol.AdHocStopped:
				return nil
			}
			select {
			case <-ctx.Done():
				lost = true
			case <-renew.C:
				if err := n.call(ctx, endpoint, "renew", registration, nil); err != nil {
					lost = true
				}
			case <-ticker.C:
				if err := n.call(ctx, endpoint, "status", registration, &status); err != nil {
					lost = true
				}
			}
		}
		ticker.Stop()
		renew.Stop()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = n.call(cleanupCtx, endpoint, "unregister", registration, nil)
		cancel()
		current = localpublisher.Endpoint{}
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}

func privateAdHocLimits(options Limits, traffic trafficlimits.Selection) *privateprotocol.AdHocLimits {
	limits := &privateprotocol.AdHocLimits{Requests: options.HTTP.Total, Concurrency: options.HTTP.Concurrency}
	if options.HTTP.Rate.Count != 0 {
		limits.Rate = &privateprotocol.AdHocRateLimit{Requests: options.HTTP.Rate.Count,
			Per: options.HTTP.Rate.Per.String(), Burst: options.HTTP.Rate.Burst}
	}
	if traffic != (trafficlimits.Selection{}) {
		limits.Traffic = &privateprotocol.AdHocTrafficLimits{Connections: options.Traffic.Connections}
		if options.Traffic.Rate.Count != 0 || options.Traffic.Rate.Burst != 0 || options.Traffic.Rate.Per != 0 {
			limits.Traffic.Rate = &privateprotocol.AdHocTrafficRate{Count: options.Traffic.Rate.Count,
				Per: options.Traffic.Rate.Per.String(), Burst: options.Traffic.Rate.Burst}
		}
		if options.Traffic.Upload != "" || options.Traffic.Download != "" {
			limits.Traffic.Bandwidth = &privateprotocol.AdHocTrafficBandwidth{
				Upload: options.Traffic.Upload, Download: options.Traffic.Download}
		}
	}
	if limits.Requests == 0 && limits.Rate == nil && limits.Concurrency == 0 && limits.Traffic == nil {
		return nil
	}
	return limits
}
