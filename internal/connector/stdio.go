package connector

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/config"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"golang.org/x/sys/unix"
)

func runConnectStdio(ctx context.Context, session *Session, service controlv1.Service, input *os.File, output io.Writer) error {
	configuration, err := connectConfiguration(ctx, session, supervisor.Job{ServiceID: service.Id,
		IdentityID: session.identity.Identity.Id, Protocol: config.ProtocolTCP, TrustRevision: service.TrustRevision, Endpoint: service.Endpoint})
	if err != nil {
		return err
	}
	local, err := openConnectStdio(input, output)
	if err != nil {
		return err
	}
	return connectorstream.Stream(ctx, local, configuration)
}

// duplicate pipe descriptors in nonblocking mode so cancellation can interrupt
// a blocked read or write and join both workers, even while ssh keeps stdin open.
// authentication completes before these descriptors are opened or read.
func pollableStdio(file *os.File) (*os.File, error) {
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), file.Name()), nil
}

func openConnectStdio(input *os.File, output io.Writer) (*connectStdio, error) {
	reader, err := pollableStdio(input)
	if err != nil {
		return nil, err
	}
	writer := io.WriteCloser(nopWriteCloser{output})
	if file, ok := output.(*os.File); ok {
		writer, err = pollableStdio(file)
		if err != nil {
			_ = reader.Close()
			return nil, err
		}
	}
	return &connectStdio{input: reader, output: writer}, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

type connectStdio struct {
	input  *os.File
	output io.WriteCloser
}

func (c *connectStdio) Read(p []byte) (int, error) {
	n, err := c.input.Read(p)
	if errors.Is(err, os.ErrClosed) {
		err = net.ErrClosed
	}
	return n, err
}
func (c *connectStdio) Write(p []byte) (int, error) {
	n, err := c.output.Write(p)
	if errors.Is(err, os.ErrClosed) {
		err = net.ErrClosed
	}
	return n, err
}
func (c *connectStdio) Close() error { return errors.Join(c.input.Close(), c.output.Close()) }
func (c *connectStdio) CloseWrite() error {
	// the remote stream has ended. stop waiting for an ssh process that may
	// keep its input pipe open until its ProxyCommand exits.
	_ = c.Close()
	return nil
}
func (*connectStdio) LocalAddr() net.Addr  { return stdioAddress{} }
func (*connectStdio) RemoteAddr() net.Addr { return stdioAddress{} }
func (c *connectStdio) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *connectStdio) SetReadDeadline(t time.Time) error { return c.input.SetReadDeadline(t) }
func (c *connectStdio) SetWriteDeadline(t time.Time) error {
	if file, ok := c.output.(*os.File); ok {
		return file.SetWriteDeadline(t)
	}
	return errors.ErrUnsupported
}

type stdioAddress struct{}

func (stdioAddress) Network() string { return "stdio" }
func (stdioAddress) String() string  { return "stdio" }
