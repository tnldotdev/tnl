package main

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/tcpconnect"
	"github.com/tnldotdev/tnl/internal/tcpport"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type connectCommand struct {
	remoteFlags `embed:""`
	URL         string `arg:"" name:"url" help:"Exact Redis public URL ID or hostname from tnl url available."`
	Listen      string `name:"listen" default:"127.0.0.1:0" help:"Numeric loopback TCP address; port 0 chooses a free port."`
}

// the current server's Redis visitor protocol starts with TLS. PostgreSQL
// and MySQL have separate startup exchanges; a generic TLS dialer cannot
// speak those protocols until the server supplies a connect contract.
func connectTarget(item controlv1.AvailablePublicURL) (tcpconnect.Options, error) {
	host, err := naming.CanonicalizeHostname(item.CanonicalHostname)
	if err != nil || host != item.CanonicalHostname || net.ParseIP(host) != nil || !opaqueid.Valid(item.Id, opaqueid.PublicURLPrefix) || item.PublicPort == nil || !tcpport.Valid(int(*item.PublicPort)) || item.ServiceProtocol != "redis" {
		return tcpconnect.Options{}, failure.Wrap("select visitor TCP public URL", failure.ServerResponseInvalid, errors.New("a Redis public URL with a valid hostname and port is required"))
	}
	return tcpconnect.Options{PublicURLID: item.Id, Hostname: host, Port: int(*item.PublicPort)}, nil
}

func runConnect(ctx context.Context, flags connectCommand, diagnostics io.Writer) error {
	// reject remote or malformed listeners before reading any saved session.
	listener, err := tcpconnect.Listen(flags.Listen)
	if err != nil {
		return failure.Wrap("select local TCP listener", failure.InvalidCommand, err)
	}
	defer listener.Close()
	selector := flags.URL
	if !opaqueid.Valid(selector, opaqueid.PublicURLPrefix) {
		host, err := naming.CanonicalizeHostname(selector)
		if err != nil || host != selector || net.ParseIP(selector) != nil {
			return failure.Wrap("select visitor TCP public URL", failure.InvalidCommand, errors.New("use an exact public URL ID or hostname"))
		}
	}
	session, err := openTeamSession(ctx, flags.remoteFlags, "tnl connect", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveVisitorPublicURL(ctx, session, selector)
	if err != nil {
		return err
	}
	options, err := connectTarget(item)
	if err != nil {
		return err
	}
	if err := writeHumanFrame(diagnostics, "tnl connect", "listening", "", clioutput.Fields(
		clioutput.Field{Label: "local", Value: listener.Addr().String()},
		clioutput.Field{Label: "public URL", Value: options.Hostname},
	)); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	// a foreground invocation owns one local connection. background listener
	// supervision belongs to the separate service manager, not this command.
	local, err := listener.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return failure.Wrap("accept local TCP connection", failure.TransportUnavailable, err)
	}
	defer local.Close()
	options.Certificate, _, err = createVisitorCertificate(ctx, session.authenticated.Control, options.PublicURLID)
	if err != nil {
		return err
	}
	return tcpconnect.Connect(ctx, options, local)
}
