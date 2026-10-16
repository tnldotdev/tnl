package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/filelock"
)

type detachedCommand struct {
	List detachedListCommand `cmd:"" help:"List detached publications for this client state."`
	Stop detachedStopCommand `cmd:"" help:"Stop a detached publication."`
}
type detachedListCommand struct {
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
}
type detachedStopCommand struct {
	detachedListCommand `embed:""`
	ID                  string `arg:"" name:"id" help:"Detached publication ID."`
}

type detachedControlKey struct{}

type detachedControl struct {
	mu    sync.Mutex
	state string
}

func (c *detachedControl) set(state string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != "stopping" {
		c.state = state
	}
}

func (c *detachedControl) get() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func detachedPublicationStarting(ctx context.Context) {
	if control, ok := ctx.Value(detachedControlKey{}).(*detachedControl); ok {
		control.set("starting")
	}
}

func detachedPublicationReady(ctx context.Context) {
	if control, ok := ctx.Value(detachedControlKey{}).(*detachedControl); ok {
		control.set("ready")
	}
}

func detachedDir(root string) string { return filepath.Join(root, "d") }

func validDetachedID(id string) bool {
	if len(id) != 24 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func detachedSocket(root, id string) (string, error) {
	if !validDetachedID(id) {
		return "", failure.Wrap("select detached publication", failure.InvalidTunnelFlags, errors.New("invalid detached publication ID"))
	}
	return filepath.Join(detachedDir(root), id), nil
}

// the child owns a private socket for its lifetime; a stale PID cannot cause
// a later unrelated process to be stopped.
func serveDetached(ctx context.Context, root, id string) (context.Context, func(), error) {
	return serveDetachedWithOptions(ctx, root, id, clientstate.OpenOptions{})
}

func serveDetachedWithOptions(ctx context.Context, root, id string, options clientstate.OpenOptions) (context.Context, func(), error) {
	if !validDetachedID(id) {
		return ctx, nil, failure.Wrap("select detached publication", failure.InvalidTunnelFlags, errors.New("invalid detached publication ID"))
	}
	state, err := clientstate.OpenWithOptions(ctx, root, options)
	if err != nil {
		return ctx, nil, err
	}
	root = state.Root()
	if err := state.Close(); err != nil {
		return ctx, nil, err
	}
	dir := detachedDir(root)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return ctx, nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByCurrentUser(info) {
		return ctx, nil, failure.Wrap("open detached state", failure.ClientStateUnavailable, errors.New("unsafe detached directory"))
	}
	path, err := detachedSocket(root, id)
	if err != nil {
		return ctx, nil, err
	}
	lock, err := filelock.Acquire(path+".lock", filelock.Nonblocking, os.Geteuid())
	if errors.Is(err, filelock.ErrLocked) {
		return ctx, nil, failure.Wrap("start detached publication", failure.ServerConflict, errors.New("detached publication already owns this ID"))
	}
	if err != nil {
		return ctx, nil, err
	}
	releaseLock := true
	defer func() {
		if releaseLock {
			_ = lock.Close()
		}
	}()
	// net.Listen unlinks an existing unix socket. never take another child's
	// control address, even if its ID was passed explicitly.
	if _, err := os.Lstat(path); err == nil {
		return ctx, nil, failure.Wrap("start detached publication", failure.ServerConflict, errors.New("detached control socket already exists"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return ctx, nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return ctx, nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		os.Remove(path)
		return ctx, nil, err
	}
	child, cancel := context.WithCancel(ctx)
	control := &detachedControl{state: "booting"}
	child = context.WithValue(child, detachedControlKey{}, control)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			var request [16]byte
			n, err := conn.Read(request[:])
			if err == nil {
				switch strings.TrimSpace(string(request[:n])) {
				case "status":
					_, _ = fmt.Fprintf(conn, "%s %d\n", control.get(), os.Getpid())
				case "stop":
					control.set("stopping")
					_, _ = io.WriteString(conn, "stopping\n")
					cancel()
				}
			}
			_ = conn.Close()
		}
	}()
	var once sync.Once
	releaseLock = false
	return child, func() { once.Do(func() { cancel(); listener.Close(); <-done; os.Remove(path); _ = lock.Close() }) }, nil
}

func detachedRequest(root, id, request string) (string, error) {
	path, err := detachedSocket(root, id)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || !ownedByCurrentUser(info) {
		return "", failure.Wrap("inspect detached publication", failure.ClientStateUnavailable, errors.New("unsafe detached socket"))
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, request+"\n"); err != nil {
		return "", err
	}
	var response [64]byte
	n, err := conn.Read(response[:])
	return strings.TrimSpace(string(response[:n])), err
}

func detachPublish(ctx context.Context, args []string, stateDir string, output io.Writer) error {
	root, err := clientStateRoot(stateDir)
	if err != nil {
		return err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	root = state.Root()
	if err := state.Close(); err != nil {
		return err
	}
	var bytes [12]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(bytes[:])
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	childArgs := make([]string, 0, len(args)+1)
	for _, arg := range args {
		if arg != "--detach" && arg != "--detach=true" {
			childArgs = append(childArgs, arg)
		}
	}
	childArgs = append(childArgs, "--detached-child="+id)
	cmd, err := startDetachedProcess(binary, childArgs)
	if err != nil {
		return err
	}
	return awaitDetached(ctx, cmd, root, id, 30*time.Second, output)
}

func detachedStatus(root, id string) (string, string, error) {
	response, err := detachedRequest(root, id, "status")
	if err != nil {
		return "", "", err
	}
	parts := strings.Fields(response)
	if len(parts) != 2 || (parts[0] != "booting" && parts[0] != "starting" && parts[0] != "ready" && parts[0] != "stopping") {
		return "", "", failure.Wrap("inspect detached publication", failure.ClientStateUnavailable, errors.New("invalid detached control response"))
	}
	if pid, err := strconv.Atoi(parts[1]); err != nil || pid <= 0 {
		return "", "", failure.Wrap("inspect detached publication", failure.ClientStateUnavailable, errors.New("invalid detached control response"))
	}
	return parts[0], parts[1], nil
}

// the process handle stays owned until readiness or an observed exit. a failed
// start is reaped; timeout stops the socket owner, then kills only that child.
func awaitDetached(ctx context.Context, cmd *exec.Cmd, root, id string, timeout time.Duration, output io.Writer) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	cleanup := func() {
		grace := time.NewTimer(2 * time.Second)
		defer grace.Stop()
		for {
			// the child may still be opening its socket when the deadline
			// fires. keep requesting stop until it exits or grace expires.
			_, _ = detachedRequest(root, id, "stop")
			select {
			case <-done:
				removeDeadDetachedSocket(root, id)
				return
			case <-grace.C:
				_ = cmd.Process.Kill()
				<-done
				removeDeadDetachedSocket(root, id)
				return
			case <-time.After(30 * time.Millisecond):
			}
		}
	}
	for {
		select {
		case <-done:
			removeDeadDetachedSocket(root, id)
			return failure.Wrap("start detached publication", failure.DetachedStartFailed, errors.New("detached process exited before publication was ready"))
		default:
		}
		state, pid, err := detachedStatus(root, id)
		if err == nil && state == "ready" {
			select {
			case <-done:
				removeDeadDetachedSocket(root, id)
				return failure.Wrap("start detached publication", failure.DetachedStartFailed, errors.New("detached process exited before publication was ready"))
			default:
			}
			if err := writeHumanFrame(output, "tnl publish", "detached", "", clioutput.Fields(clioutput.Field{Label: "id", Value: id}, clioutput.Field{Label: "pid", Value: pid}, clioutput.Field{Label: "state", Value: state})); err != nil {
				cleanup()
				return err
			}
			return nil
		}
		select {
		case <-ctx.Done():
			cleanup()
			return ctx.Err()
		case <-deadline.C:
			cleanup()
			return failure.Wrap("start detached publication", failure.DetachedStartFailed, errors.New("detached publication did not become ready"))
		case <-done:
			removeDeadDetachedSocket(root, id)
			return failure.Wrap("start detached publication", failure.DetachedStartFailed, errors.New("detached process exited before publication was ready"))
		case <-time.After(30 * time.Millisecond):
		}
	}
}

func removeDeadDetachedSocket(root, id string) {
	path, err := detachedSocket(root, id)
	if err != nil {
		return
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || !ownedByCurrentUser(info) {
		return
	}
	if _, err := detachedRequest(root, id, "status"); err == nil {
		return
	}
	current, err := os.Lstat(path)
	if err == nil && current.Mode()&os.ModeSocket != 0 && ownedByCurrentUser(current) && os.SameFile(info, current) {
		_ = os.Remove(path)
	}
}

func startDetachedProcess(binary string, args []string) (*exec.Cmd, error) {
	cmd := exec.Command(binary, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func runDetachedList(flags detachedListCommand, output io.Writer) error {
	root, err := existingDetachedRoot(flags.StateDir)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(detachedDir(root))
	if errors.Is(err, os.ErrNotExist) {
		entries = nil
		err = nil
	}
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{}
	for _, entry := range entries {
		id := entry.Name()
		if !validDetachedID(id) {
			continue
		}
		state, pid, err := detachedStatus(root, id)
		if err != nil {
			blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "id", Value: id}, clioutput.Field{Label: "state", Value: "stopped"}))
			continue
		}
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "id", Value: id}, clioutput.Field{Label: "pid", Value: pid}, clioutput.Field{Label: "state", Value: state}))
	}
	state := "no publications"
	if len(blocks) > 0 {
		state = "detached"
	}
	return writeHumanFrame(output, "tnl detached list", state, "", blocks...)
}

func runDetachedStop(flags detachedStopCommand, output io.Writer) error {
	root, err := existingDetachedRoot(flags.StateDir)
	if err != nil {
		return err
	}
	state, _, err := detachedStatus(root, flags.ID)
	if err != nil {
		return failure.Wrap("stop detached publication", failure.DetachedNotFound, err)
	}
	if state == "stopping" {
		return failure.Wrap("stop detached publication", failure.DetachedNotFound, errors.New("detached publication is already stopping"))
	}
	if _, err := detachedRequest(root, flags.ID, "stop"); err != nil {
		return failure.Wrap("stop detached publication", failure.DetachedNotFound, err)
	}
	return writeHumanFrame(output, "tnl detached stop", "stopping", "", clioutput.Fields(clioutput.Field{Label: "id", Value: flags.ID}))
}

func existingDetachedRoot(stateDir string) (string, error) {
	root, err := clientStateRoot(stateDir)
	if err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(root)
	if errors.Is(err, os.ErrNotExist) {
		return root, nil
	}
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByCurrentUser(info) {
		return "", failure.Wrap("inspect detached state", failure.ClientStateUnavailable, errors.New("unsafe detached state directory"))
	}
	return canonical, nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
