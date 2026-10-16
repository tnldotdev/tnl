// package managedssh serves SSH for a host-managed publication.
package managedssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	"github.com/tnldotdev/tnl/internal/livevisitor"
	"golang.org/x/crypto/ssh"
)

var (
	ErrConfiguration = errors.New("managed SSH configuration is invalid")
	ErrUnauthorized  = fmt.Errorf("managed SSH access is denied: %w", livevisitor.ErrDenied)
	ErrUnavailable   = errors.New("managed SSH child is unavailable")
)

// identity comes from the authenticated outer visitor TLS connection, never
// from the SSH username, environment, key, or channel payload.
type Identity struct {
	IdentityID  string
	PublicURLID string
}

type Decision struct {
	IdentityID  string
	PublicURLID string
	SSHUser     string
	ValidUntil  time.Time
}

type Config struct {
	HostKey ssh.Signer
	Users   []string
	// Authorize must honor context cancellation. it checks the current control
	// grant for the supplied TLS identity and exact requested OS username.
	Authorize func(context.Context, Identity, string) (Decision, error)
	Runner    *Runner
	// positive decisions are refreshed at this interval, or earlier at expiry.
	// zero selects 30 seconds. unknown decisions reject new work while existing
	// work retains only its last successful deadline; explicit denials close it.
	RecheckInterval time.Duration
	MaxChannels     int
}

type childRunner interface {
	Run(context.Context, Request, Streams) (int, error)
	Dial(context.Context, string, string) (net.Conn, error)
}

type Server struct {
	config        Config
	runner        childRunner
	validateUsers func([]string) error
}

func New(config Config) (*Server, error) {
	if os.Getuid() != 0 {
		return nil, ErrConfiguration
	}
	return newServer(config, os.Geteuid(), ValidateUsers)
}

// validation injection is private to safe same-uid protocol tests.
func newServer(config Config, euid int, validate func([]string) error) (*Server, error) {
	if euid != 0 || config.HostKey == nil || config.Authorize == nil || ValidateUserNames(config.Users) != nil || validate == nil || config.RecheckInterval < 0 || config.MaxChannels < 0 || config.MaxChannels > 256 {
		return nil, ErrConfiguration
	}
	if config.RecheckInterval == 0 {
		config.RecheckInterval = 30 * time.Second
	}
	if config.MaxChannels == 0 {
		config.MaxChannels = 32
	}
	config.Users = slices.Clone(config.Users)
	if config.Runner == nil {
		config.Runner = &Runner{}
	}
	return &Server{config: config, runner: config.Runner, validateUsers: validate}, nil
}

// ServeConn takes ownership of conn and joins all child work before returning.
// the caller must complete and authorize outer mTLS before handing it over.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn, identity Identity) error {
	if conn == nil {
		return ErrConfiguration
	}
	defer conn.Close()
	if identity.IdentityID == "" || identity.PublicURLID == "" {
		return ErrUnauthorized
	}
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	permission := &connectionPermission{}
	life = context.WithValue(life, permissionKey{}, permission)
	stopClose := context.AfterFunc(life, func() { _ = conn.Close() })
	defer stopClose()
	work := &connectionWork{limit: s.config.MaxChannels}
	var result error
	var authDone sync.WaitGroup
	server := &gliderssh.Server{
		HostSigners: []gliderssh.Signer{s.config.HostKey},
		Version:     "tnl", HandshakeTimeout: 10 * time.Second,
		// explicit empty maps avoid mutable library defaults and all reverse
		// forwarding handlers. only session and direct-tcpip are installed.
		RequestHandlers: map[string]gliderssh.RequestHandler{},
		ChannelHandlers: map[string]gliderssh.ChannelHandler{},
		ServerConfigCallback: func(gliderssh.Context) *ssh.ServerConfig {
			return &ssh.ServerConfig{
				MaxAuthTries: 1,
				// use this attempt's exact username. gliderssh's context caches
				// metadata from the first authentication attempt.
				NoClientAuthCallback: func(metadata ssh.ConnMetadata) (*ssh.Permissions, error) {
					username := metadata.User()
					checkCtx, stop := context.WithTimeout(life, 10*time.Second)
					decision, err := s.authorize(checkCtx, identity, username)
					stop()
					if err != nil {
						return nil, ErrUnauthorized
					}
					permission.set(decision, true)
					authDone.Go(func() {
						s.renew(life, identity, username, decision, permission, cancel)
					})
					return nil, nil
				},
			}
		},
		ConnectionFailedCallback: func(_ net.Conn, err error) { result = err },
	}
	wrap := func(handle func(context.Context, *ssh.ServerConn, ssh.NewChannel)) gliderssh.ChannelHandler {
		return func(_ *gliderssh.Server, sshConn *ssh.ServerConn, channel ssh.NewChannel, _ gliderssh.Context) {
			if !permission.current() {
				_ = channel.Reject(ssh.Prohibited, "SSH authorization is unavailable")
				return
			}
			if !work.start() {
				_ = channel.Reject(ssh.ResourceShortage, "channel limit reached")
				return
			}
			defer work.done()
			handle(life, sshConn, channel)
		}
	}
	server.ChannelHandlers["session"] = wrap(s.serveSession)
	server.ChannelHandlers["direct-tcpip"] = wrap(s.serveForward)
	server.HandleConn(conn)
	cancel()
	work.join()
	authDone.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return result
}

func (s *Server) authorize(ctx context.Context, identity Identity, username string) (Decision, error) {
	if !slices.Contains(s.config.Users, username) || s.validateUsers([]string{username}) != nil {
		return Decision{}, ErrUnauthorized
	}
	requested := time.Now()
	decision, err := s.config.Authorize(ctx, identity, username)
	if err != nil {
		return Decision{}, err
	}
	if ctx.Err() != nil {
		return Decision{}, ctx.Err()
	}
	if decision.IdentityID != identity.IdentityID || decision.PublicURLID != identity.PublicURLID || decision.SSHUser != username || !time.Now().Before(decision.ValidUntil) {
		return Decision{}, ErrUnauthorized
	}
	decision.ValidUntil = minTime(decision.ValidUntil, requested.Add(livevisitor.MaxLifetime))
	return decision, nil
}

func (s *Server) renew(ctx context.Context, identity Identity, username string, decision Decision, permission *connectionPermission, cancel context.CancelFunc) {
	for {
		delay := min(s.config.RecheckInterval, max(time.Millisecond, time.Until(decision.ValidUntil)/2))
		timer := time.NewTimer(max(delay, 0))
		expires := time.AfterFunc(max(time.Until(decision.ValidUntil), 0), cancel)
		select {
		case <-ctx.Done():
			timer.Stop()
			expires.Stop()
			return
		case <-timer.C:
		}
		permission.set(decision, false)
		// the last decision is a hard deadline even if control stops answering.
		checkCtx, stop := context.WithDeadline(ctx, minTime(time.Now().Add(5*time.Second), decision.ValidUntil))
		next, err := s.authorize(checkCtx, identity, username)
		stop()
		expires.Stop()
		if errors.Is(err, livevisitor.ErrDenied) || errors.Is(err, livevisitor.ErrExpired) || ctx.Err() != nil || !time.Now().Before(decision.ValidUntil) {
			cancel()
			return
		}
		if err == nil {
			decision = next
			permission.set(decision, true)
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

type permissionKey struct{}
type connectionPermission struct {
	mu    sync.Mutex
	known bool
	until time.Time
}

func (p *connectionPermission) set(decision Decision, known bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.known, p.until = known, decision.ValidUntil
}
func (p *connectionPermission) current() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.known && time.Now().Before(p.until)
}
func canStartWork(ctx context.Context) bool {
	p, ok := ctx.Value(permissionKey{}).(*connectionPermission)
	return ok && ctx.Err() == nil && p.current()
}

// gliderssh starts channel handlers in goroutines. closing the start gate before
// joining also covers handlers scheduled after HandleConn has returned.
type connectionWork struct {
	mu     sync.Mutex
	wg     sync.WaitGroup
	closed bool
	active int
	limit  int
}

func (w *connectionWork) start() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.active >= w.limit {
		return false
	}
	w.active++
	w.wg.Add(1)
	return true
}

func (w *connectionWork) done() {
	w.mu.Lock()
	w.active--
	w.mu.Unlock()
	w.wg.Done()
}

func (w *connectionWork) join() {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	w.wg.Wait()
}
