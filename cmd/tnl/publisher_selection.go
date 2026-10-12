package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/dockertarget"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

func selectedPublisherEndpoint(ctx context.Context, project projectConfiguration) (localPublisherEndpoint, error) {
	selection := project.Config.Publisher
	if selection == nil || selection.Type == "local" {
		return localPublisherEndpoint{}, errors.New("the project uses the local publisher")
	}
	credential, err := readPublisherOwnerCredential(project.Root, selection.CredentialFile())
	if err != nil {
		return localPublisherEndpoint{}, err
	}
	url := ""
	if selection.Type == "url" {
		url = *selection.URL
	} else {
		container, err := dockertarget.SelectContainer(ctx, project.Root, project.Worktree.Label.FullLabel, selection.DockerSelection)
		if err != nil {
			return localPublisherEndpoint{}, failure.Wrap("connect to Docker publisher", failure.ClientStateUnavailable, err)
		}
		address, err := dockertarget.HostPort(container, *selection.ContainerPort, true)
		if err != nil {
			return localPublisherEndpoint{}, failure.Wrap("connect to Docker publisher", failure.ClientStateUnavailable, err)
		}
		url = "http://" + address
	}
	return localPublisherEndpoint{Version: privateprotocol.Version, URL: url, Credential: credential}, nil
}

func remotePublisherScope(ctx context.Context, project projectConfiguration, app, adHoc bool, service string) (localPublisherEndpoint, error) {
	owner, err := selectedPublisherEndpoint(ctx, project)
	if err != nil {
		return localPublisherEndpoint{}, err
	}
	client := namedPublisherClient{endpoint: owner, http: publisherHTTPClient(10 * time.Second)}
	var snapshot localpublisherv1.ProjectSnapshot
	if err := client.request(ctx, http.MethodGet, "/v1/status", "", nil, &snapshot); err != nil {
		return localPublisherEndpoint{}, err
	}
	if snapshot.Project != project.Root {
		return localPublisherEndpoint{}, failure.Wrap("select project publisher", failure.ProjectConfigInvalid,
			errors.New("publisher project directory differs; mount the worktree at the same path as the host"))
	}
	if !app && !adHoc {
		return owner, nil
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

func readPublisherOwnerCredential(root, selected string) (string, error) {
	path := selected
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", failure.Wrap("read publisher owner credential", failure.PublisherOwnerCredentialMissing, err)
		}
		return "", failure.Wrap("read publisher owner credential", failure.ClientStateUnavailable, err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner.Uid != uint32(os.Getuid()) {
		return "", failure.Wrap("read publisher owner credential", failure.ClientStateUnavailable,
			errors.New("owner credential must be a user-owned regular file with mode 0600"))
	}
	file, err := os.Open(path)
	if err != nil {
		return "", failure.Wrap("read publisher owner credential", failure.ClientStateUnavailable, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", failure.Wrap("read publisher owner credential", failure.ClientStateUnavailable,
			errors.New("owner credential file changed while opening it"))
	}
	data, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil {
		return "", failure.Wrap("read publisher owner credential", failure.ClientStateUnavailable, err)
	}
	if len(data) > 128 {
		return "", failure.Wrap("read publisher owner credential", failure.ProjectConfigInvalid, errors.New("publisher owner credential is too large"))
	}
	credential := strings.TrimSpace(string(data))
	decoded, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil || len(decoded) != 32 || len(credential) != 43 {
		return "", failure.Wrap("read publisher owner credential", failure.ProjectConfigInvalid,
			errors.New("owner credential file must contain one 32-byte base64url token"))
	}
	return credential, nil
}

func dockerTargetInsidePublisher(service string, port int, http bool) string {
	address := net.JoinHostPort(service, fmt.Sprint(port))
	if http {
		return "http://" + address
	}
	return address
}
