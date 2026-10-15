package localpublisher

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/publishertarget"
)

// ComposeBoundary adapts the same owner API to its verified container network.
// the inner capability middleware still performs authentication and scoping.
// loopback remains available for docker compose exec, with its own authority.
type ComposeBoundary struct {
	Docker    publishertarget.Runner
	Placement publishertarget.Placement
	Project   string
	File      string
	Service   string
	Port      int
	StateRoot string
}

func (b ComposeBoundary) URL() string {
	return "http://" + net.JoinHostPort(b.Service, strconv.Itoa(b.Port))
}

func (b ComposeBoundary) ListenAddress() (string, error) {
	if b.Port < 1 || b.Port > 65535 || !validComposeService(b.Service) || b.Placement.NetworkID == "" || b.Placement.OwnerID == "" || b.Placement.Worktree.Label.FullLabel == "" {
		return "", errors.New("compose owner requires service, port, network, container, and host worktree identity")
	}
	return net.JoinHostPort("0.0.0.0", strconv.Itoa(b.Port)), nil
}

func validComposeService(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return value[0] != '-' && value[0] != '.' && value[0] != '_'
}

func (b ComposeBoundary) runner() publishertarget.Runner {
	if b.Docker == nil {
		return publishertarget.CLI{}
	}
	return b.Docker
}

// ComposeNetwork chooses one explicitly worktree-labelled bridge network. an
// unrelated default bridge or an implicit first network is never selected.
func ComposeNetwork(ctx context.Context, docker publishertarget.Runner, owner publishertarget.Container, worktree string) (string, error) {
	var selected string
	for _, network := range owner.NetworkSettings.Networks {
		data, err := docker.Run(ctx, nil, "network", "inspect", "--", network.NetworkID)
		if err != nil {
			return "", err
		}
		var networks []struct {
			ID     string `json:"Id"`
			Driver string
			Scope  string
			Labels map[string]string
		}
		if json.Unmarshal(data, &networks) != nil {
			return "", errors.New("invalid docker network response")
		}
		if len(networks) != 1 || networks[0].ID != network.NetworkID {
			return "", errors.New("docker network identity changed")
		}
		current := networks[0]
		if current.Labels[publishertarget.WorktreeLabel] != worktree || worktree == "" {
			continue
		}
		if current.Driver != "bridge" || current.Scope != "local" || selected != "" {
			return "", errors.New("compose publisher requires one worktree-labelled local bridge network")
		}
		selected = current.ID
	}
	if selected == "" {
		return "", errors.New("label the private compose network with tnl.worktree")
	}
	return selected, nil
}

func (b ComposeBoundary) Handler(capabilities *privateprotocol.Capabilities, next http.Handler) http.Handler {
	local, _ := url.Parse(capabilities.Owner().Url)
	public, _ := url.Parse(b.URL())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		peer, peerErr := netip.ParseAddr(host)
		if err != nil || peerErr != nil || len(r.Header.Values("Origin")) != 0 || r.URL.IsAbs() || r.Host != public.Host && r.Host != local.Host || r.Host == local.Host && !peer.IsLoopback() {
			Problem(w, privateprotocol.ErrUnauthorized)
			return
		}
		if !peer.IsLoopback() {
			if err := b.validatePeer(r.Context(), peer); err != nil {
				Problem(w, privateprotocol.ErrUnauthorized)
				return
			}
		}
		request := r.Clone(r.Context())
		request.Host = local.Host
		request.RemoteAddr = "127.0.0.1:1"
		next.ServeHTTP(w, request)
	})
}

func (b ComposeBoundary) validatePeer(ctx context.Context, peer netip.Addr) error {
	docker := b.runner()
	if err := publishertarget.Local(ctx, docker); err != nil {
		return err
	}
	owner, err := publishertarget.Inspect(ctx, docker, b.Placement.OwnerID)
	if err != nil || owner.Config.Labels[publishertarget.WorktreeLabel] != b.Placement.Worktree.Label.FullLabel {
		return errors.New("compose owner identity changed")
	}
	attached := false
	for _, network := range owner.NetworkSettings.Networks {
		attached = attached || network.NetworkID == b.Placement.NetworkID
	}
	if !attached {
		return errors.New("compose owner is outside the selected network")
	}
	// resolve network membership afresh: a reused IP cannot inherit a previous
	// container's authorization to reach the capability boundary.
	data, err := docker.Run(ctx, nil, "container", "ls", "--quiet", "--no-trunc", "--filter", "network="+b.Placement.NetworkID)
	if err != nil {
		return err
	}
	for _, id := range strings.Fields(string(data)) {
		container, err := publishertarget.Inspect(ctx, docker, id)
		if err != nil {
			return err
		}
		for _, network := range container.NetworkSettings.Networks {
			address, _ := netip.ParseAddr(network.IPAddress)
			address6, _ := netip.ParseAddr(network.GlobalIPv6Address)
			if network.NetworkID == b.Placement.NetworkID && (address == peer || address6 == peer) {
				labels := container.Config.Labels
				if labels[publishertarget.WorktreeLabel] != b.Placement.Worktree.Label.FullLabel || labels["com.docker.compose.project"] != b.Project || !publishertarget.ComposeFilesMatch(b.Placement.ProjectRoot, b.File, labels["com.docker.compose.project.config_files"]) || labels["com.docker.compose.project.working_dir"] != b.Placement.ProjectRoot || strings.ToLower(labels["com.docker.compose.oneoff"]) != "false" {
					return errors.New("request came from another project")
				}
				return nil
			}
		}
	}
	return errors.New("request came from outside the compose network")
}
