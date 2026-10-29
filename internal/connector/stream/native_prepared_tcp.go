package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// PreparedNativeTCP owns one already opened, signed and TLS-verified native TCP
// stream. it is single-use: local arrival cannot select a run, sign, perform ICE,
// call control, reset setup time, or replace the target after live bytes fail.
// the pair/session owner must close these children before replacing its run.
type PreparedNativeTCP struct {
	ctx          context.Context
	conn         net.Conn
	mu           sync.Mutex
	taken        bool
	closed       bool
	stop         func() bool
	callbackDone chan struct{}
	physicalOnce sync.Once
	physicalErr  error
	closeOnce    sync.Once
	closeErr     error
	work         sync.WaitGroup
}

// PrepareNativeTCP consumes a source-prepared opening outside local arrival.
// this is not a publisher permission constructor: the publisher independently
// checks the signed token, exact relay-attested pair, current policy and C.
func PrepareNativeTCP(ctx context.Context, session muxsession.Session, run Run, entry tunnelv1.NativePeerVisitorEntry) (*PreparedNativeTCP, error) {
	if ctx == nil || ctx.Err() != nil || session == nil || run.Protocol != "tcp" || run.Endpoint == nil || run.ServiceTLS == nil || run.ServiceTLS.InsecureSkipVerify || len(run.ServiceTLS.Certificates) != 0 || run.ServiceTLS.GetClientCertificate != nil || !run.ValidUntil.After(time.Now()) ||
		run.ServiceID != entry.ServiceID || run.ServiceRunID != entry.ServiceRunID || run.RunNumber != entry.RunNumber || run.TrustRevision < 1 || uint64(run.TrustRevision) != entry.MetadataRevision {
		return nil, ErrServiceConnection
	}
	public, keyErr := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.PublicKey)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(entry.Permission.Signature)
	message, messageErr := tunnelv1.NativePeerProofMessage(entry, nil)
	if keyErr != nil || signatureErr != nil || messageErr != nil || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, message, signature) {
		return nil, ErrServiceConnection
	}
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := session.OpenStream(setup)
	if err != nil {
		return nil, err
	}
	setupDone := make(chan struct{})
	stopSetup := context.AfterFunc(setup, func() { defer close(setupDone); _ = raw.Close() })
	setupStopped := false
	defer func() {
		if !setupStopped && !stopSetup() {
			<-setupDone
		}
	}()
	owned := false
	defer func() {
		if !owned {
			_ = raw.Close()
		}
	}()
	deadline, _ := setup.Deadline()
	if run.ValidUntil.Before(deadline) {
		deadline = run.ValidUntil
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := tunnelv1.WriteNativePeerVisitorOpening(raw, entry, nil); err != nil {
		return nil, err
	}
	writer := tunnel.NewNativeRequestWriter(raw)
	trust := run.ServiceTLS.Clone()
	trust.ServerName = run.Endpoint.Hostname
	trust.MinVersion = max(trust.MinVersion, tls.VersionTLS12)
	secured := tls.Client(writer, trust)
	if err := secured.HandshakeContext(setup); err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !run.ValidUntil.After(time.Now()) {
		return nil, ErrServiceConnection
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// clearing a transport deadline may race with timeout cleanup. promotion
	// requires both the original budget and exclusive ownership of that cleanup.
	if setup.Err() != nil || !time.Now().Before(deadline) || !stopSetup() {
		return nil, ErrServiceConnection
	}
	setupStopped = true
	p := &PreparedNativeTCP{ctx: ctx, conn: secured, callbackDone: make(chan struct{})}
	p.stop = context.AfterFunc(ctx, func() { defer close(p.callbackDone); _ = p.closePhysical() })
	owned = true
	return p, nil
}

func (p *PreparedNativeTCP) closePhysical() error {
	p.physicalOnce.Do(func() { p.physicalErr = p.conn.Close() })
	return p.physicalErr
}

func (p *PreparedNativeTCP) finish() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		p.closeErr = p.closePhysical()
		if !p.stop() {
			<-p.callbackDone
		}
	})
}

func (p *PreparedNativeTCP) Close() error {
	if p == nil {
		return nil
	}
	p.finish()
	p.work.Wait()
	return p.closeErr
}

// Forward consumes this one prepared stream and joins both copy directions.
// failure is final; the session's siblings and packet endpoint remain owned by
// their existing owner, not by this local connection.
func (p *PreparedNativeTCP) Forward(ctx context.Context, local net.Conn) (result error) {
	if p == nil || local == nil {
		return ErrServiceConnection
	}
	p.mu.Lock()
	if p.closed || p.taken || p.ctx.Err() != nil || ctx.Err() != nil {
		p.mu.Unlock()
		return ErrServiceConnection
	}
	p.taken = true
	p.work.Add(1)
	p.mu.Unlock()
	defer p.work.Done()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(closed); _ = local.Close(); _ = p.closePhysical() })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	defer local.Close()
	defer func() { p.finish(); result = errors.Join(result, p.closeErr) }()
	_, err := streamcopy.Copy(local, &preparedNativeUse{owner: p, ctx: ctx})
	return err
}

var _ interface{ Close() error } = (*PreparedNativeTCP)(nil)

// the existing prepared owner is the dispatch fence too. no separate stamp or
// policy mirror is needed, and optimized io.Copy methods cannot escape it.
type preparedNativeUse struct {
	owner *PreparedNativeTCP
	ctx   context.Context
}

func (c *preparedNativeUse) current() error {
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	if c.owner.closed || c.owner.ctx.Err() != nil || c.ctx.Err() != nil {
		return ErrServiceConnection
	}
	return nil
}
func (c *preparedNativeUse) Read(p []byte) (int, error) {
	if err := c.current(); err != nil {
		return 0, err
	}
	n, err := c.owner.conn.Read(p)
	if n > 0 {
		if current := c.current(); current != nil {
			return 0, current
		}
	}
	return n, err
}
func (c *preparedNativeUse) Write(p []byte) (int, error) {
	if err := c.current(); err != nil {
		return 0, err
	}
	return c.owner.conn.Write(p)
}
func (c *preparedNativeUse) CloseWrite() error {
	if err := c.current(); err != nil {
		return err
	}
	if writer, ok := c.owner.conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.ErrUnsupported
}
func (c *preparedNativeUse) Close() error {
	c.owner.mu.Lock()
	c.owner.closed = true
	c.owner.mu.Unlock()
	return c.owner.closePhysical()
}
func (c *preparedNativeUse) LocalAddr() net.Addr            { return c.owner.conn.LocalAddr() }
func (c *preparedNativeUse) RemoteAddr() net.Addr           { return c.owner.conn.RemoteAddr() }
func (c *preparedNativeUse) SetDeadline(at time.Time) error { return c.owner.conn.SetDeadline(at) }
func (c *preparedNativeUse) SetReadDeadline(at time.Time) error {
	return c.owner.conn.SetReadDeadline(at)
}
func (c *preparedNativeUse) SetWriteDeadline(at time.Time) error {
	return c.owner.conn.SetWriteDeadline(at)
}
