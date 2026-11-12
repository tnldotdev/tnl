package tnl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

type boundedOutput struct{ bytes.Buffer }

var errApplicationStoppedBeforeReady = errors.New("native publication stopped before it was routable")

func (b *boundedOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > publisherprotocol.MaxBytes {
		return 0, errors.New("native endpoint response exceeds size limit")
	}
	return b.Buffer.Write(data)
}

func startApplicationRuntime(ctx context.Context, options Options, invocation string) (publisherprotocol.Endpoint, error) {
	directory := options.Directory
	if directory == "" {
		var err error
		directory, err = os.Getwd()
		if err != nil {
			return publisherprotocol.Endpoint{}, err
		}
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	binary := options.Binary
	if binary == "" {
		binary = "tnl"
	}
	args := []string{"--no-telemetry", "runtime", "endpoint", "--directory", directory, "--invocation-id", invocation}
	if options.StateDir != "" {
		args = append(args, "--state-dir", options.StateDir)
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(startup, binary, args...)
	command.WaitDelay = 5 * time.Second
	var output boundedOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return publisherprotocol.Endpoint{}, errors.Join(context.Cause(startup), err)
	}
	var endpoint publisherprotocol.Endpoint
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&endpoint); err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return publisherprotocol.Endpoint{}, errors.New("native endpoint returned trailing data")
	}
	if publisherprotocol.ValidateEndpoint(endpoint) != nil || endpoint.Scope != "invocation" || endpoint.InvocationId == nil || *endpoint.InvocationId != invocation {
		return publisherprotocol.Endpoint{}, publisherprotocol.ErrForbidden
	}
	if err := publisherprotocol.Call(ctx, endpoint, "GET", "/v1/health", nil, nil); err != nil {
		return publisherprotocol.Endpoint{}, err
	}
	return endpoint, nil
}

// capture before requesting publication: its worker can finish before the first
// acknowledgment or status read. later snapshots must not skip that terminal event.
func applicationCursor(ctx context.Context, endpoint publisherprotocol.Endpoint) (string, error) {
	var snapshot publisherapp.Snapshot
	if err := publisherprotocol.Call(ctx, endpoint, "GET", "/v1/status", nil, &snapshot); err != nil {
		return "", errors.Join(context.Cause(ctx), err)
	}
	if snapshot.SchemaVersion != 1 || !validApplicationCursor(snapshot.Cursor) {
		return "", errors.New("native status returned an invalid event cursor")
	}
	return snapshot.Cursor, nil
}

func validApplicationCursor(cursor string) bool {
	return cursor != "" && len(cursor) <= 128
}

func sameApplicationService(service publisherapp.Service, accepted publisherprotocol.AcceptedPublication, invocation string) bool {
	return service.Name == invocation && service.RegistrationID == accepted.Registration.RegistrationID && service.Target == accepted.Registration.Target && service.PublicURL == accepted.PublicUrl
}

func observeApplication(ctx context.Context, endpoint publisherprotocol.Endpoint, accepted publisherprotocol.AcceptedPublication, invocation, cursor string, ready chan<- struct{}) error {
	poll := time.NewTicker(250 * time.Millisecond)
	defer poll.Stop()
	renew := time.NewTicker(5 * time.Second)
	defer renew.Stop()
	routable := false
	for {
		var events []publisherapp.Event
		if err := publisherprotocol.Call(ctx, endpoint, "GET", "/v1/events?after="+url.QueryEscape(cursor), nil, &events); err != nil {
			// an expired cursor has lost the completion boundary. do not reset it
			// from status and guess whether the missing worker already stopped.
			return errors.Join(context.Cause(ctx), err)
		}
		for _, event := range events {
			if !validApplicationCursor(event.Cursor) || event.Cursor == cursor {
				return errors.New("native events returned an invalid resume cursor")
			}
			cursor = event.Cursor
			if event.Service == nil || !sameApplicationService(*event.Service, accepted, invocation) {
				continue
			}
			switch event.Type {
			case "service.failed":
				return errors.New("native publication failed: " + event.Service.Failure)
			case "service.stopped":
				if event.Service.Failure != "" {
					return errors.New("native publication failed: " + event.Service.Failure)
				}
				if !routable {
					return errApplicationStoppedBeforeReady
				}
				return nil
			}
		}
		var snapshot publisherapp.Snapshot
		if err := publisherprotocol.Call(ctx, endpoint, "GET", "/v1/status", nil, &snapshot); err != nil {
			return errors.Join(context.Cause(ctx), err)
		}
		found := false
		for _, service := range snapshot.Services {
			if service.Name != invocation {
				continue
			}
			found = sameApplicationService(service, accepted, invocation)
			if !found || !service.Registered {
				return publisherapp.ErrRegistrationStale
			}
			if service.Failure != "" {
				return errors.New("native publication failed: " + service.Failure)
			}
			if service.Routable && service.RunNumber > 0 {
				routable = true
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
		if !found {
			return publisherapp.ErrRegistrationStale
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-renew.C:
			if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/renew", accepted.Registration, nil); err != nil {
				return errors.Join(context.Cause(ctx), err)
			}
		case <-poll.C:
		}
	}
}
