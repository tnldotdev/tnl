package localpublisher

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

var selectDockerPublisher = dockerPublisherClient

func selectedPublisherClient(ctx context.Context, project projectConfiguration, timeout time.Duration) (namedPublisherClient, error) {
	return selectDockerPublisher(ctx, project, timeout)
}

func remotePublisherScope(ctx context.Context, project projectConfiguration, app, adHoc bool, service string) (localPublisherEndpoint, error) {
	client, err := selectedPublisherClient(ctx, project, 10*time.Second)
	if err != nil {
		return localPublisherEndpoint{}, err
	}
	owner := client.endpoint
	var snapshot localpublisherv1.ProjectSnapshot
	if err := client.request(ctx, http.MethodGet, "/v1/status", "", nil, &snapshot); err != nil {
		return localPublisherEndpoint{}, err
	}
	if snapshot.Project != project.Root {
		return localPublisherEndpoint{}, failure.Wrap("select project publisher", failure.ProjectConfigInvalid,
			errors.New("publisher project directory differs; mount the worktree at the same path as the host"))
	}
	if !app && !adHoc {
		return localPublisherEndpoint{}, failure.Wrap("select publisher owner", failure.InvalidCommand, errors.New("use a Docker owner request from the host CLI"))
	}
	path := "/v1/scopes/ad-hoc?export=1"
	if app {
		path = "/v1/scopes/app/" + service + "?export=1"
	}
	var issued localPublisherEndpoint
	if err := client.request(ctx, http.MethodPost, path, "", nil, &issued); err != nil {
		return localPublisherEndpoint{}, err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(issued.Credential)
	if err != nil || issued.Version != privateprotocol.Version || len(issued.Credential) != 43 || len(decoded) != 32 || issued.Credential == owner.Credential {
		return localPublisherEndpoint{}, failure.Wrap("issue scoped publisher credential", failure.ServerResponseInvalid, errors.New("publisher returned an invalid credential"))
	}
	return localPublisherEndpoint{Version: privateprotocol.Version, URL: owner.URL, Credential: issued.Credential}, nil
}

func rejectPublisherRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func publisherHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: rejectPublisherRedirect,
		Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
}

func dockerTargetInsidePublisher(service string, port int, http bool) string {
	address := net.JoinHostPort(service, fmt.Sprint(port))
	if http {
		return "http://" + address
	}
	return address
}
