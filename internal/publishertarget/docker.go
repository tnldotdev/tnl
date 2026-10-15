// package publishertarget discovers exact, worktree-scoped private listeners.
package publishertarget

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const WorktreeLabel = "tnl.worktree"

// Runner keeps Docker discovery testable without replacing the identity checks.
// input is used only by exec's stdin, never by a shell or command-line argument.
type Runner interface {
	Run(context.Context, []byte, ...string) ([]byte, error)
}

type CLI struct{}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8<<20 {
		return 0, errors.New("docker response exceeds 8 MiB")
	}
	return b.Buffer.Write(p)
}

func (CLI) Run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	command.Stdin = bytes.NewReader(input)
	var output boundedBuffer
	command.Stdout = &output
	// docker stderr can contain application output and credentials. return only
	// the operation and exit status; never include it in diagnostics.
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("docker command failed: %w", err)
	}
	return output.Bytes(), nil
}

type Binding struct {
	HostIP   string
	HostPort string
}

type Network struct {
	NetworkID         string
	IPAddress         string
	GlobalIPv6Address string
}

type Mount struct {
	Type        string
	Name        string
	Source      string
	Destination string
	RW          bool
}

type Container struct {
	ID     string `json:"Id"`
	Name   string
	Config struct {
		Labels map[string]string
		Env    []string
	}
	State struct {
		Running    bool
		Restarting bool
		Dead       bool
	}
	NetworkSettings struct {
		Ports    map[string][]Binding
		Networks map[string]Network
	}
	Mounts []Mount
}

func (c Container) Live() bool { return c.State.Running && !c.State.Restarting && !c.State.Dead }

// Local rejects remote daemon contexts even if they happen to publish a port
// resembling localhost. unix sockets are the only supported Docker endpoints.
func Local(ctx context.Context, docker Runner) error {
	if host := os.Getenv("DOCKER_HOST"); host != "" && os.Getenv("DOCKER_CONTEXT") == "" {
		return localHost(host)
	}
	args := []string{"context", "inspect"}
	if name := os.Getenv("DOCKER_CONTEXT"); name != "" {
		args = append(args, name)
	}
	data, err := docker.Run(ctx, nil, args...)
	if err != nil {
		return err
	}
	var contexts []struct {
		Endpoints map[string]struct{ Host string }
	}
	if json.Unmarshal(data, &contexts) != nil || len(contexts) != 1 {
		return errors.New("docker context must select one local daemon")
	}
	return localHost(contexts[0].Endpoints["docker"].Host)
}

func localHost(host string) error {
	u, err := url.Parse(host)
	if err != nil || u.Scheme != "unix" || u.Host != "" || !strings.HasPrefix(u.Path, "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("container targets require a local Docker unix socket")
	}
	return nil
}

func Inspect(ctx context.Context, docker Runner, identifier string) (Container, error) {
	if !validIdentifier(identifier) {
		return Container{}, errors.New("select an exact container name or full ID")
	}
	data, err := docker.Run(ctx, nil, "container", "inspect", "--", identifier)
	if err != nil {
		return Container{}, err
	}
	var containers []Container
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		return Container{}, errors.New("docker inspect did not return one container")
	}
	c := containers[0]
	if len(c.ID) != 64 || !validHex(c.ID) || identifier != c.ID && identifier != strings.TrimPrefix(c.Name, "/") {
		return Container{}, errors.New("docker container identifier was not an exact match")
	}
	if !c.Live() {
		return Container{}, errors.New("selected container is not running")
	}
	return c, nil
}

func validHex(value string) bool {
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return value != ""
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || value[0] == '-' {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func published(c Container, port int) (string, error) {
	bindings := c.NetworkSettings.Ports[strconv.Itoa(port)+"/tcp"]
	addresses := map[netip.AddrPort]bool{}
	for _, binding := range bindings {
		address, err := netip.ParseAddr(binding.HostIP)
		number, numberErr := strconv.ParseUint(binding.HostPort, 10, 16)
		if err != nil || numberErr != nil || number == 0 || address.Zone() != "" || !address.IsLoopback() && !address.IsUnspecified() {
			return "", errors.New("container port must have one local published TCP binding")
		}
		if address.IsUnspecified() {
			if address.Is4() {
				address = netip.MustParseAddr("127.0.0.1")
			} else {
				address = netip.IPv6Loopback()
			}
		}
		addresses[netip.AddrPortFrom(address.Unmap(), uint16(number))] = true
	}
	if len(addresses) != 1 {
		return "", errors.New("container port must have one unambiguous local published TCP binding")
	}
	for address := range addresses {
		return address.String(), nil
	}
	panic("unreachable")
}
