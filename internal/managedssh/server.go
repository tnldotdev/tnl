// package managedssh serves SSH for a host-managed publication.
package managedssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// identity is returned by control for this exact SSH attempt.
type Identity struct {
	IdentityID  string
	PublicURLID string
	SessionID   string
}

// binding is built from the trusted relay stream and the completed SSH key
// exchange. session id is the hex-encoded SSH transport session hash.
type Binding struct {
	Hostname, PublicURLID, PublishRunID, VisitorConnectionID string
	PublishRunNumber                                         uint64
	Source                                                   netip.AddrPort
	Username, SessionID                                      string
}

type Attempt struct {
	ID, ApprovalURL, Code string
	ValidUntil            time.Time
}

type AttemptDecision struct {
	Binding    Binding
	IdentityID string
	Approved   bool
	ValidUntil time.Time
}

// PublisherSSHAttempt is the expected publisher-to-control boundary. start
// returns an opaque ID, a control-host HTTPS URL without the code, a separate
// eight-character base32 code, and a deadline at most five minutes away. wait
// returns only a terminal decision. claim atomically consumes the approved
// attempt for the supplied exact binding; cancel invalidates it on exit.
// recheck returns current access for the claimed identity and account. decision
// responses echo the exact binding and give a hard permission deadline. all
// calls must honor cancellation and authenticate the scoped publish run token.
type PublisherSSHAttempt interface {
	StartSSHAttempt(context.Context, Binding) (Attempt, error)
	WaitSSHAttempt(context.Context, string) (AttemptDecision, error)
	ClaimSSHAttempt(context.Context, string, Binding) (AttemptDecision, error)
	CancelSSHAttempt(context.Context, string) error
	RecheckSSHSession(context.Context, Binding, string) (AttemptDecision, error)
}

var approvalCode = regexp.MustCompile(`^[A-Z2-7]{8}$`)

func validAttempt(a Attempt, controlOrigin string) bool {
	u, err := url.Parse(a.ApprovalURL)
	origin, originErr := url.Parse(controlOrigin)
	return a.ID != "" && len(a.ID) <= 128 && len(a.ApprovalURL) <= 2048 && approvalCode.MatchString(a.Code) && err == nil && originErr == nil && origin.Scheme == "https" && origin.Host != "" && origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == "" && u.Scheme == origin.Scheme && u.Host == origin.Host && u.User == nil && u.Fragment == "" && u.RawQuery == "" && !strings.Contains(a.ApprovalURL, a.Code) && time.Now().Before(a.ValidUntil) && !a.ValidUntil.After(time.Now().Add(5*time.Minute))
}

func validDecision(d AttemptDecision, bound Binding) bool {
	return d.Approved && d.Binding == bound && d.IdentityID != "" && time.Now().Before(d.ValidUntil)
}

type Decision struct {
	IdentityID  string
	PublicURLID string
	SSHUser     string
	ValidUntil  time.Time
}

type Config struct {
	HostKey    ssh.Signer
	Users      []string
	Attempts   PublisherSSHAttempt
	ControlURL string
	// binding contains trusted source, run, visitor id and host-side SSH account.
	Binding Binding
	// promote must receive ingress acknowledgement before auth succeeds.
	Promote func(context.Context) error
	// Authorize rechecks the live claimed identity and exact account.
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
	if euid != 0 || config.HostKey == nil || config.Authorize == nil || config.Attempts == nil || config.Promote == nil || ValidateUserNames(config.Users) != nil || validate == nil || config.RecheckInterval < 0 || config.MaxChannels < 0 || config.MaxChannels > 256 {
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
// the caller must verify trusted PROXY v2 and relay run metadata first.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return ErrConfiguration
	}
	defer conn.Close()
	bound := s.config.Binding
	if bound.Hostname == "" || bound.PublicURLID == "" || bound.PublishRunID == "" || bound.PublishRunNumber == 0 || bound.VisitorConnectionID == "" || !bound.Source.IsValid() || bound.Source.Addr().Zone() != "" {
		return ErrUnauthorized
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	guarded := &approvalConn{Conn: conn}
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	permission := &connectionPermission{}
	life = context.WithValue(life, permissionKey{}, permission)
	stopClose := context.AfterFunc(life, func() { _ = conn.Close() })
	defer stopClose()
	work := &connectionWork{limit: s.config.MaxChannels}
	var result error
	var authDone sync.WaitGroup
	var pending Attempt
	var ready bool
	var identity Identity
	defer func() {
		if pending.ID != "" {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer stop()
			_ = s.config.Attempts.CancelSSHAttempt(cleanup, pending.ID)
		}
	}()
	server := &gliderssh.Server{
		HostSigners: []gliderssh.Signer{s.config.HostKey},
		Version:     "tnl",
		BannerHandler: func(metadata gliderssh.Context) string {
			if pending.ID != "" {
				return ""
			}
			bound.Username, bound.SessionID = metadata.User(), metadata.SessionID()
			if !slices.Contains(s.config.Users, bound.Username) || s.validateUsers([]string{bound.Username}) != nil || bound.SessionID == "" || life.Err() != nil {
				return ""
			}
			startCtx, stop := context.WithTimeout(life, 5*time.Second)
			defer stop()
			a, err := s.config.Attempts.StartSSHAttempt(startCtx, bound)
			pending = a
			if err != nil || !validAttempt(a, s.config.ControlURL) || life.Err() != nil {
				return ""
			}
			ready = true
			_ = conn.SetDeadline(a.ValidUntil)
			return fmt.Sprintf("open %s\ncode: %s\napprove %s on the control host; this SSH connection will continue automatically\n", a.ApprovalURL, a.Code, bound.Username)
		},
		KeyboardInteractiveHandler: func(metadata gliderssh.Context, _ ssh.KeyboardInteractiveChallenge) bool {
			actual := bound
			actual.Username, actual.SessionID = metadata.User(), metadata.SessionID()
			if !ready || actual != bound || life.Err() != nil {
				return false
			}
			// SSH parsing is paused in this callback. any further client input,
			// including EOF, invalidates the waiting attempt without a prompt.
			guarded.watch(cancel)
			waitCtx, stop := context.WithDeadline(life, pending.ValidUntil)
			defer stop()
			decision, err := s.config.Attempts.WaitSSHAttempt(waitCtx, pending.ID)
			if err != nil || !validDecision(decision, bound) || life.Err() != nil || !time.Now().Before(pending.ValidUntil) {
				return false
			}
			claim, err := s.config.Attempts.ClaimSSHAttempt(waitCtx, pending.ID, bound)
			if err != nil || !validDecision(claim, bound) || claim.IdentityID != decision.IdentityID || life.Err() != nil {
				return false
			}
			identity = Identity{IdentityID: claim.IdentityID, PublicURLID: bound.PublicURLID, SessionID: bound.SessionID}
			checkCtx, checkStop := context.WithTimeout(waitCtx, 5*time.Second)
			current, err := s.authorize(checkCtx, identity, bound.Username)
			checkStop()
			if err != nil || waitCtx.Err() != nil || life.Err() != nil || !time.Now().Before(current.ValidUntil) {
				return false
			}
			current.ValidUntil = minTime(current.ValidUntil, claim.ValidUntil)
			promoteCtx, promoteStop := context.WithTimeout(waitCtx, 10*time.Second)
			err = s.config.Promote(promoteCtx)
			promoteStop()
			if err != nil || waitCtx.Err() != nil || life.Err() != nil || !time.Now().Before(current.ValidUntil) {
				return false
			}
			_ = conn.SetDeadline(time.Time{})
			permission.set(current, true)
			authDone.Go(func() { s.renew(life, identity, bound.Username, current, permission, cancel) })
			guarded.resume()
			return true
		},
		// explicit empty maps avoid mutable library defaults and all reverse
		// forwarding handlers. only session and direct-tcpip are installed.
		RequestHandlers: map[string]gliderssh.RequestHandler{},
		ChannelHandlers: map[string]gliderssh.ChannelHandler{},
		ServerConfigCallback: func(gliderssh.Context) *ssh.ServerConfig {
			return &ssh.ServerConfig{
				MaxAuthTries: 1,
				NoClientAuth: false,
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
	server.HandleConn(guarded)
	cancel()
	work.join()
	authDone.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return result
}

// approvalConn reads one post-auth-request byte while control waits. after
// approval it replays that byte to SSH, avoiding a concurrent read or a
// deadline interruption of the SSH parser. EOF cancels the pending attempt.
type approvalConn struct {
	net.Conn
	watching     atomic.Bool
	approved     atomic.Bool
	preauthBytes atomic.Int64
	done         chan struct{}
	first        [1]byte
	n            int
	err          error
	mu           sync.Mutex
}

func (c *approvalConn) watch(cancel context.CancelFunc) {
	c.done = make(chan struct{})
	c.watching.Store(true)
	go func() {
		c.n, c.err = c.Conn.Read(c.first[:])
		if !c.approved.Load() {
			cancel()
		}
		close(c.done)
	}()
}
func (c *approvalConn) resume() { c.approved.Store(true) }
func (c *approvalConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.watching.Load() {
		<-c.done
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.watching.Load() {
			c.watching.Store(false)
			if c.n != 0 {
				if !c.approved.Load() {
					return 0, ErrUnauthorized
				}
				b[0] = c.first[0]
				return 1, c.err
			}
			return 0, c.err
		}
	}
	n, err := c.Conn.Read(b)
	if !c.approved.Load() && c.preauthBytes.Add(int64(n)) > 64<<10 {
		_ = c.Conn.Close()
		return 0, ErrUnauthorized
	}
	return n, err
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
