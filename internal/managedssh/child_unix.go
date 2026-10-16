//go:build linux || darwin

package managedssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func validWindow(w Window) bool {
	return w.Width >= 0 && w.Width <= 65535 && w.Height >= 0 && w.Height <= 65535
}

func validateSetup(s childSetup) error {
	r := s.Request
	if !validWindow(r.Window) || len(r.Command) > 64<<10 || strings.ContainsRune(r.Command, 0) || len(r.Term) > 128 {
		return errChildSetup
	}
	for _, c := range r.Term {
		if c < 33 || c > 126 {
			return errChildSetup
		}
	}
	if !validTerminalModes(r.Modes) || r.Term == "" && len(r.Modes) != 0 {
		return errChildSetup
	}
	switch r.Kind {
	case "shell":
		if r.Command != "" || s.Address != "" {
			return errChildSetup
		}
	case "command":
		if s.Address != "" {
			return errChildSetup
		}
	case "sftp":
		if r.Command != "" || r.Term != "" || s.Address != "" {
			return errChildSetup
		}
	case "dial":
		if r.Command != "" || r.Term != "" || len(s.Address) > 1024 {
			return errChildSetup
		}
		host, port, err := net.SplitHostPort(s.Address)
		if err != nil || host == "" || strings.ContainsAny(host, "\x00\r\n") {
			return errChildSetup
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errChildSetup
		}
	default:
		return errChildSetup
	}
	_, err := lookupAccount(r.Username)
	return err
}

type childProcess struct {
	cmd     *exec.Cmd
	status  *os.File
	resize  *os.File
	decoder *json.Decoder
	cancel  context.CancelFunc
}

func (r *Runner) start(ctx context.Context, setup childSetup, streams Streams, socket *os.File) (*childProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateSetup(setup); err != nil {
		return nil, err
	}
	if !r.allowSameUID && (os.Getuid() != 0 || os.Geteuid() != 0) {
		return nil, errRootRequired
	}
	data, err := json.Marshal(setup)
	if err != nil || len(data) > maxSetup {
		return nil, errChildSetup
	}
	exe := r.Executable
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return nil, err
		}
	}
	args := r.Args
	if args == nil {
		args = []string{"runtime", "ssh-child"}
	}
	configR, configW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer configR.Close()
	defer configW.Close()
	statusR, statusW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer statusW.Close()
	resizeR, resizeW, err := os.Pipe()
	if err != nil {
		statusR.Close()
		return nil, err
	}
	defer resizeR.Close()
	childCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(childCtx, exe, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.ExtraFiles = []*os.File{configR, statusW, resizeR}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	if socket != nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = socket, socket, io.Discard
	} else {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = streams.Stdin, streams.Stdout, streams.Stderr
	}
	if err := cmd.Start(); err != nil {
		cancel()
		statusR.Close()
		resizeW.Close()
		return nil, fmt.Errorf("start ssh child: %w", err)
	}
	p := &childProcess{cmd: cmd, status: statusR, resize: resizeW, decoder: json.NewDecoder(statusR), cancel: cancel}
	// retain no parent-side reader that could keep a failed child's pipe alive.
	statusW.Close()
	configR.Close()
	resizeR.Close()
	if _, err := configW.Write(data); err != nil {
		configW.Close()
		p.stop()
		return nil, errChildSetup
	}
	configW.Close()
	var ready childStatus
	if err := p.decoder.Decode(&ready); err != nil || !ready.Ready || ready.Failed {
		p.stop()
		return nil, errChildSetup
	}
	return p, nil
}

func (p *childProcess) stop() { p.cancel(); p.resize.Close(); p.status.Close(); _ = p.cmd.Wait() }

// Run runs a shell, command, or sftp server under the selected account.
func (r *Runner) Run(ctx context.Context, req Request, streams Streams) (int, error) {
	if req.Kind == "dial" {
		return 0, errChildSetup
	}
	p, err := r.start(ctx, childSetup{Request: req}, streams, nil)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, err
	}
	defer p.cancel()
	defer p.status.Close()
	defer p.resize.Close()
	done := make(chan struct{})
	var controls sync.WaitGroup
	defer func() { close(done); _ = p.resize.Close(); controls.Wait() }()
	if req.Term != "" && streams.Resize != nil || streams.Signals != nil {
		controls.Go(func() {
			enc := json.NewEncoder(p.resize)
			windows, signals := streams.Resize, streams.Signals
			for {
				select {
				case <-done:
					return
				case w, ok := <-windows:
					if !ok {
						windows = nil
						continue
					}
					if validWindow(w) {
						if enc.Encode(childControl{Window: &w}) != nil {
							return
						}
					}
				case signal, ok := <-signals:
					if !ok {
						signals = nil
						continue
					}
					if validSignal(signal) && enc.Encode(childControl{Signal: signal}) != nil {
						return
					}
				}
			}
		})
	}
	var result childStatus
	statusErr := p.decoder.Decode(&result)
	if streams.CloseInput != nil {
		streams.CloseInput()
	}
	waitErr := p.cmd.Wait()
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if statusErr != nil || result.Failed || waitErr != nil {
		return 0, errChildSetup
	}
	if result.Signal != "" && streams.ExitSignal != nil {
		streams.ExitSignal(result.Signal)
	}
	return result.ExitCode, nil
}

type childConn struct {
	*net.UnixConn
	p    *childProcess
	once sync.Once
	err  error
	done chan struct{}
}

func (c *childConn) Close() error {
	c.once.Do(func() {
		c.err = c.UnixConn.Close()
		c.p.stop()
		close(c.done)
	})
	return c.err
}

// Dial opens the target in a dropped-privilege child and returns its byte stream.
func (r *Runner) Dial(ctx context.Context, username, address string) (net.Conn, error) {
	syscall.ForkLock.RLock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, err
	}
	local, remote := os.NewFile(uintptr(fds[0]), "ssh-dial-parent"), os.NewFile(uintptr(fds[1]), "ssh-dial-child")
	defer local.Close()
	defer remote.Close()
	conn, err := net.FileConn(local)
	if err != nil {
		return nil, err
	}
	p, err := r.start(ctx, childSetup{Request: Request{Username: username, Kind: "dial"}, Address: address}, Streams{}, remote)
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	c := &childConn{UnixConn: conn.(*net.UnixConn), p: p, done: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-c.done:
		}
	}()
	if ctx.Err() != nil {
		c.Close()
		return nil, ctx.Err()
	}
	return c, nil
}

// RunChild is the private installed-binary entry point; fd 3 is its only setup source.
func RunChild(ctx context.Context) error { return runChild(ctx, false) }

func runChild(ctx context.Context, sameUID bool) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	if !sameUID && (os.Getuid() != 0 || os.Geteuid() != 0) {
		return errRootRequired
	}
	config := os.NewFile(3, "ssh-child-setup")
	status := os.NewFile(4, "ssh-child-status")
	// register the inherited control pipe with go's poller so Close joins its
	// reader instead of leaving a blocking read behind at shell exit.
	if unix.SetNonblock(5, true) != nil {
		return errChildSetup
	}
	resize := os.NewFile(5, "ssh-child-resize")
	defer config.Close()
	defer status.Close()
	defer resize.Close()
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	unix.CloseOnExec(5)
	if err := closeInheritedDescriptors(); err != nil {
		return errChildSetup
	}
	enc := json.NewEncoder(status)
	fail := func() error { _ = enc.Encode(childStatus{Failed: true}); return errChildSetup }
	data, err := io.ReadAll(io.LimitReader(config, maxSetup+1))
	if err != nil || len(data) > maxSetup {
		return fail()
	}
	config.Close()
	var setup childSetup
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if dec.Decode(&setup) != nil {
		return fail()
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || validateSetup(setup) != nil {
		return fail()
	}
	a, err := lookupAccount(setup.Request.Username)
	if err != nil || dropAccount(a, sameUID) != nil {
		return fail()
	}
	if os.Chdir(a.home) != nil {
		return fail()
	}
	os.Clearenv()
	for _, entry := range cleanEnvironment(a, setup.Request.Term) {
		key, value, _ := strings.Cut(entry, "=")
		_ = os.Setenv(key, value)
	}
	if setup.Request.Kind == "dial" {
		return childDial(ctx, setup.Address, enc)
	}
	if setup.Request.Kind == "sftp" {
		server, err := sftp.NewServer(childStdio{})
		if err != nil {
			return fail()
		}
		defer server.Close()
		if enc.Encode(childStatus{Ready: true}) != nil {
			return errChildSetup
		}
		go func() { <-ctx.Done(); os.Stdin.Close(); os.Stdout.Close() }()
		err = server.Serve()
		if err != nil && !errors.Is(err, io.EOF) {
			return fail()
		}
		return enc.Encode(childStatus{})
	}
	return childShell(ctx, a, setup.Request, resize, enc)
}

func cleanEnvironment(a account, term string) []string {
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + a.home, "USER=" + a.name, "LOGNAME=" + a.name, "SHELL=" + a.shell}
	if term != "" {
		env = append(env, "TERM="+term)
	}
	return env
}

type childStdio struct{}

func (childStdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (childStdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (childStdio) Close() error                { return errors.Join(os.Stdin.Close(), os.Stdout.Close()) }

func childDial(ctx context.Context, address string, status *json.Encoder) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		_ = status.Encode(childStatus{Failed: true})
		return errChildSetup
	}
	defer conn.Close()
	if err := status.Encode(childStatus{Ready: true}); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
		_ = unix.Shutdown(0, unix.SHUT_RD)
		_ = unix.Shutdown(1, unix.SHUT_WR)
	})
	defer stop()
	inputDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, os.Stdin)
		_ = conn.(*net.TCPConn).CloseWrite()
		if err != nil {
			conn.Close()
		}
		inputDone <- err
	}()
	_, outputErr := io.Copy(os.Stdout, conn)
	// target EOF closes only the output direction: the visitor may still write.
	_ = unix.Shutdown(1, unix.SHUT_WR)
	if outputErr != nil {
		conn.Close()
		_ = unix.Shutdown(0, unix.SHUT_RD)
	}
	return errors.Join(outputErr, <-inputDone)
}

func childShell(ctx context.Context, a account, req Request, resize *os.File, status *json.Encoder) error {
	args := []string(nil)
	if req.Kind == "command" {
		args = []string{"-c", req.Command}
	}
	cmd := exec.Command(a.shell, args...)
	cmd.Dir, cmd.Env = a.home, cleanEnvironment(a, req.Term)
	var terminal *os.File
	var terminalMu sync.Mutex
	var outputDone chan struct{}
	var err error
	if req.Term != "" {
		w := req.Window
		if w.Width == 0 {
			w.Width = 80
		}
		if w.Height == 0 {
			w.Height = 24
		}
		var slave *os.File
		terminal, slave, err = pty.Open()
		if err == nil {
			err = pty.Setsize(terminal, &pty.Winsize{Cols: uint16(w.Width), Rows: uint16(w.Height)})
		}
		if err == nil {
			err = applyTerminalModes(slave, req.Modes)
		}
		if err == nil {
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			err = cmd.Start()
		}
		if slave != nil {
			_ = slave.Close()
		}
		if err != nil && terminal != nil {
			_ = terminal.Close()
		}
		if err == nil {
			defer func() { terminalMu.Lock(); defer terminalMu.Unlock(); terminal.Close() }()
			outputDone = make(chan struct{})
			go func() { defer close(outputDone); _, _ = io.Copy(os.Stdout, terminal) }()
			go func() {
				_, _ = io.Copy(terminal, os.Stdin)
				// canonical EOF respects the negotiated control character.
				if canonical, set := req.Modes[ssh.ICANON]; set && canonical == 0 {
					return
				}
				eof := uint32(4)
				if value, ok := req.Modes[ssh.VEOF]; ok {
					eof = value
				}
				if eof != 255 && eof != disabledCharacter {
					_, _ = terminal.Write([]byte{byte(eof), byte(eof)})
				}
			}()
		}
	} else {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		err = cmd.Start()
	}
	if err != nil {
		_ = status.Encode(childStatus{Failed: true})
		return errChildSetup
	}
	var processMu sync.Mutex
	active := true
	signalShell := func(sig syscall.Signal) {
		processMu.Lock()
		defer processMu.Unlock()
		if !active {
			return
		}
		if terminal != nil {
			terminalMu.Lock()
			foreground, err := unix.IoctlGetInt(int(terminal.Fd()), unix.TIOCGPGRP)
			terminalMu.Unlock()
			if err == nil && foreground > 0 && foreground != syscall.Getpgrp() && foreground != cmd.Process.Pid {
				_ = syscall.Kill(-foreground, sig)
			}
		}
		_ = syscall.Kill(-cmd.Process.Pid, sig)
	}
	killShell := func() { signalShell(syscall.SIGKILL) }
	defer func() { processMu.Lock(); active = false; processMu.Unlock() }()
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		dec := json.NewDecoder(resize)
		for {
			var control childControl
			if dec.Decode(&control) != nil {
				return
			}
			if control.Window != nil && validWindow(*control.Window) && terminal != nil {
				terminalMu.Lock()
				current, e := pty.GetsizeFull(terminal)
				if e == nil {
					if control.Window.Width != 0 {
						current.Cols = uint16(control.Window.Width)
					}
					if control.Window.Height != 0 {
						current.Rows = uint16(control.Window.Height)
					}
					_ = pty.Setsize(terminal, current)
				}
				terminalMu.Unlock()
			}
			if sig, ok := unixSignals[control.Signal]; ok {
				signalShell(sig)
			}
		}
	}()
	defer func() { _ = resize.Close(); <-controlDone }()
	stop := context.AfterFunc(ctx, killShell)
	defer stop()
	if status.Encode(childStatus{Ready: true}) != nil {
		killShell()
		_ = cmd.Wait()
		return errChildSetup
	}
	err = cmd.Wait()
	// descendants must not retain the terminal after the session leader exits.
	killShell()
	if outputDone != nil {
		<-outputDone
	}
	code := 0
	exitSignal := ""
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return errChildSetup
		}
		code = exit.ExitCode()
		if code < 0 {
			sig := cmd.ProcessState.Sys().(syscall.WaitStatus).Signal()
			code = 128 + int(sig)
			exitSignal = signalName(sig)
		}
	}
	return status.Encode(childStatus{ExitCode: code, Signal: exitSignal})
}

func closeInheritedDescriptors() error {
	path := "/proc/self/fd"
	if _, err := os.Stat(path); err != nil {
		path = "/dev/fd"
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd <= 5 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		// go's runtime descriptors are already close-on-exec and must remain live.
		if err == nil && flags&unix.FD_CLOEXEC == 0 {
			if err := unix.Close(fd); err != nil && !errors.Is(err, unix.EBADF) {
				return err
			}
		}
	}
	return nil
}
