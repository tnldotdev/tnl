package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
)

type pingCommand struct {
	URL       string           `arg:"" name:"address" help:"Hostname, URL, host:port, or exact service ID."`
	Expect    string           `name:"expect" enum:"2xx" help:"Exit nonzero unless the HTTP response is 2xx."`
	Output    statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
	ServerURL string           `name:"server" env:"TNL_SERVER" help:"Control URL for service ID lookup; defaults to the selected server."`
	StateDir  string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory for service ID lookup."`
}

func runPing(ctx context.Context, flags pingCommand, output, diagnostics io.Writer) error {
	value := flags.URL
	selector, err := naming.ParseServiceSelector(value)
	if err != nil {
		return failure.Wrap("select visitor address", failure.InvalidCommand, &pingFailure{state: "invalid address", cause: err})
	}
	if selector.Kind == naming.SelectorID {
		value, err = resolvePingAddress(ctx, flags, selector.ID, diagnostics)
		if err != nil {
			return err
		}
		selector, err = naming.ParseServiceSelector(value)
		if err != nil {
			return failure.Wrap("read service endpoint", failure.ServerResponseInvalid, err)
		}
	}
	address, protocol, dialAddress, err := pingAddress(selector, value)
	if err != nil {
		return failure.Wrap("select visitor address", failure.InvalidCommand, &pingFailure{state: "invalid address", cause: err})
	}
	return runPingProbe(ctx, flags, address, protocol, dialAddress, output, diagnostics)
}

func resolvePingAddress(ctx context.Context, flags pingCommand, id string, diagnostics io.Writer) (string, error) {
	session, err := openTeamSession(ctx, remoteFlags{ServerURL: flags.ServerURL, StateDir: flags.StateDir}, "tnl ping", diagnostics)
	if err != nil {
		return "", err
	}
	defer session.Close()
	service, err := resolveVisitorService(ctx, session, id)
	if err != nil {
		return "", err
	}
	return servicePublicAddress(service.Protocol, service.Endpoint)
}

func pingAddress(selector naming.ServiceSelector, value string) (address, protocol, dialAddress string, err error) {
	if selector.Kind == naming.SelectorName {
		// ping has no project-service lookup for an unqualified literal.
		return "https://" + selector.Name, "https", "", nil
	}
	if selector.Kind != naming.SelectorAddress {
		return "", "", "", errors.New("expected a visitor address")
	}
	if selector.Protocol == "http" {
		return value, selector.Scheme, "", nil
	}
	if selector.Port == 0 {
		host := value
		if strings.Contains(selector.Host, ":") {
			host = "[" + selector.Host + "]"
		}
		return "https://" + host, "https", "", nil
	}
	if selector.Scheme == "" {
		return value, "tcp", value, nil
	}
	// a scheme provides a default port but does not add a protocol check.
	// don't echo or use database URI options; only the authority is probed.
	dialAddress = net.JoinHostPort(selector.Host, strconv.Itoa(selector.Port))
	return selector.Scheme + "://" + dialAddress, "tcp", dialAddress, nil
}

func runPingProbe(ctx context.Context, flags pingCommand, address, protocol, dialAddress string, output, diagnostics io.Writer) error {
	label := "Checking HTTP response"
	if dialAddress != "" {
		if flags.Expect != "" {
			return failure.Wrap("select visitor check", failure.InvalidCommand, &pingFailure{state: "non-HTTP expectation"})
		}
		label = "Checking TCP connection"
	}
	stopProgress := clioutput.StartProgress(ctx, output, diagnostics, flags.Output != statusOutputJSON, label)
	var result publisherapp.PingResult
	if dialAddress != "" {
		result = publisherapp.PingTCP(ctx, address, dialAddress)
	} else {
		result = publisherapp.Ping(ctx, address, protocol)
	}
	stopProgress()
	if flags.Output == statusOutputJSON {
		if err := json.NewEncoder(output).Encode(result); err != nil {
			return err
		}
	} else {
		if err := writeResult(output, clioutput.Line(pingStatus(result)+"  "+result.Address)); err != nil {
			return err
		}
	}
	if result.State == "unavailable" || result.State == "tnl denied" || result.State == "invalid address" || result.State == "invalid protocol" {
		return failure.Wrap("check visitor address", failure.TunnelUnavailable, &pingFailure{state: result.State, code: result.Code, protocol: result.Protocol})
	}
	if flags.Expect == "2xx" && (result.Status < 200 || result.Status >= 300) {
		return failure.Wrap("check HTTP response", failure.TunnelUnavailable, &pingFailure{state: "HTTP expectation failed"})
	}
	return nil
}

func pingStatus(result publisherapp.PingResult) string {
	if result.Protocol == "tcp" {
		if result.State == "tcp connected" {
			return "TCP connected"
		}
		return "TCP connection failed"
	}
	if result.Status == 0 {
		return "No HTTP response"
	}
	status := "HTTP " + strconv.Itoa(result.Status)
	if name := http.StatusText(result.Status); name != "" {
		status += " " + name
	}
	if result.Code != "" {
		return status + " (tnl: " + result.Code + ")"
	}
	switch result.Status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		status += " (redirect not followed)"
	}
	return status
}

type pingFailure struct {
	state, code, protocol string
	cause                 error
}

func (e *pingFailure) Unwrap() error { return e.cause }

func (e *pingFailure) Error() string {
	if e.cause != nil {
		return e.cause.Error()
	}
	return e.state
}

func (e *pingFailure) message() string {
	switch e.state {
	case "tnl denied":
		if code := diagnostic.Code(e.code); slices.Contains(diagnostic.Codes(), code) {
			return diagnostic.Summary(code)
		}
		return "tnl rejected the request before the app responded."
	case "invalid address", "invalid protocol":
		return "provide a hostname, a full HTTP or HTTPS URL, a TCP address, or an exact service ID."
	case "non-HTTP expectation":
		return "--expect 2xx requires an HTTP or HTTPS check."
	case "HTTP expectation failed":
		return "expected an HTTP 2xx response."
	default:
		if e.protocol == "tcp" {
			return "the TCP connection failed."
		}
		return "the connection or TLS verification failed."
	}
}

func (a *commandApp) newPingCommand() *cobra.Command {
	f := a.flags
	cPing := &cobra.Command{
		Use: "ping", Short: "Check an HTTP response or TCP connection from this machine.", GroupID: "observe",
		Long: "A hostname uses HTTPS. An HTTP or HTTPS URL uses the given scheme, path, and query. tnl sends a GET request without following redirects. Any app response, even a 503, exits 0 unless you set --expect 2xx.\n\nA host:port or supported non-HTTP URL checks only whether TCP connects. A service ID uses sign-in to find the public endpoint, but the probe itself sends no credentials. Use tnl wait to check configured readiness.",
	}
	a.leaf(cPing, &f.Ping, func(call commandCall) error {
		return runPing(call.ctx, f.Ping, a.out, a.errOut)
	})
	return cPing
}
