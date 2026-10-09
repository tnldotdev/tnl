package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/filelock"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

type devBootstrap struct {
	socket         string
	lock           *filelock.Lock
	forcedPort     string
	server         *http.Server
	done           chan struct{}
	closing        chan struct{}
	configurations chan devConfigurationRequest
	targets        chan devTargetResult
	resolved       chan struct{}

	mu               sync.Mutex
	configuration    *devConfigurationRequest
	target           *devTargetRequest
	targetErr        error
	assignment       devConfigurationResponse
	configurationErr error
	serveErr         error
	resolveOnce      sync.Once
	closeOnce        sync.Once
	closeErr         error
}

type devConfigurationRequest struct {
	Protocol  int    `json:"protocol"`
	Framework string `json:"framework"`
}

type devConfigurationResponse struct {
	Protocol  int                        `json:"protocol"`
	TunnelID  string                     `json:"tunnelID"`
	Service   *string                    `json:"service"`
	Namespace string                     `json:"namespace"`
	Hostname  string                     `json:"hostname"`
	PublicURL string                     `json:"publicURL"`
	Project   projectmeta.PublicMetadata `json:"project"`
}

func nullableService(service string) *string {
	if service == "" {
		return nil
	}
	return &service
}

func runtimeProjectMetadata(
	metadata projectmeta.Metadata,
	service, namespace, hostname string,
) projectmeta.PublicMetadata {
	project := metadata.Public(true)
	if service == "" {
		project.Namespace = namespace
		return project
	}
	selected := project.Services[service]
	selected.Namespace, selected.Hostname, selected.URL = namespace, hostname, "https://"+hostname
	if selected.Paths != nil {
		paths := make(map[string]projectmeta.Path, len(selected.Paths))
		for prefix, mount := range selected.Paths {
			mount.URL = selected.URL + prefix
			paths[prefix] = mount
		}
		selected.Paths = paths
	}
	project.Services[service] = selected
	return project
}

type devTargetRequest struct {
	Protocol  int    `json:"protocol"`
	Framework string `json:"framework"`
	Target    string `json:"target"`
}

func newDevBootstrap(ctx context.Context, forcedTarget, projectRoot string, services ...string) (*devBootstrap, error) {
	forcedPort := ""
	if forcedTarget != "" {
		var err error
		forcedTarget, err = localproxy.NormalizeTarget(forcedTarget)
		if err != nil {
			return nil, err
		}
		_, forcedPort, err = net.SplitHostPort(strings.TrimPrefix(forcedTarget, "http://"))
		if err != nil {
			return nil, fmt.Errorf("read forced development target port: %w", err)
		}
	}
	if projectRoot == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve development worktree: %w", err)
		}
		worktree, err := projectconfig.ResolveWorktree(ctx, cwd)
		if err != nil {
			return nil, fmt.Errorf("resolve development worktree: %w", err)
		}
		projectRoot = worktree.Root
	}
	service := ""
	if len(services) != 0 {
		service = services[0]
	}
	dir, err := devRuntimeDirectory()
	if err != nil {
		return nil, err
	}
	stem := "dev-" + devSocketDigest(projectRoot, service)
	lock, err := acquireDevLock(filepath.Join(dir, stem+".lock"))
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		_ = lock.Close()
	}
	bootstrap := &devBootstrap{
		socket: filepath.Join(dir, stem+".sock"), lock: lock,
		forcedPort: forcedPort,
		done:       make(chan struct{}), closing: make(chan struct{}),
		configurations: make(chan devConfigurationRequest, 1), targets: make(chan devTargetResult, 1),
		resolved: make(chan struct{}),
	}
	if info, statErr := os.Lstat(bootstrap.socket); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 {
			cleanup()
			return nil, failure.Wrap("open development session socket", failure.DevSocketUnavailable, errors.New("development session socket path is occupied by a non-socket file"))
		}
		if err := os.Remove(bootstrap.socket); err != nil {
			cleanup()
			return nil, failure.Wrap("remove stale development session socket", failure.DevSocketUnavailable, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		cleanup()
		return nil, failure.Wrap("inspect development session socket", failure.DevSocketUnavailable, statErr)
	}
	listener, err := net.Listen("unix", bootstrap.socket)
	if err != nil {
		cleanup()
		return nil, failure.Wrap("listen on development session socket", failure.DevSocketUnavailable, err)
	}
	if err := os.Chmod(bootstrap.socket, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(bootstrap.socket)
		cleanup()
		return nil, failure.Wrap("secure development session socket", failure.DevSocketUnavailable, err)
	}
	bootstrap.server = &http.Server{
		Handler:           http.HandlerFunc(bootstrap.handle),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go func() {
		err := bootstrap.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		bootstrap.mu.Lock()
		bootstrap.serveErr = err
		bootstrap.mu.Unlock()
		close(bootstrap.done)
	}()
	return bootstrap, nil
}

func devSocketDigest(projectRoot, service string) string {
	digest := sha256.Sum256([]byte(projectRoot + "\x00" + service))
	return hex.EncodeToString(digest[:8])
}

func devRuntimeDirectory() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	return privateRuntimeDirectoryAt(base)
}

func privateRuntimeDirectoryAt(base string) (string, error) {
	dir := filepath.Join(base, fmt.Sprintf("tnl-%d", os.Getuid()))
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", failure.Wrap("create development runtime directory", failure.DevSocketUnavailable, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", failure.Wrap("inspect development runtime directory", failure.DevSocketUnavailable, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Getuid()) {
		return "", failure.Wrap("validate development runtime directory", failure.DevSocketUnavailable, errors.New("development runtime directory must be a user-owned directory with mode 0700"))
	}
	return dir, nil
}

func acquireDevLock(path string) (*filelock.Lock, error) {
	lock, err := filelock.Acquire(path, filelock.Nonblocking, os.Getuid())
	if errors.Is(err, filelock.ErrLocked) {
		return nil, errDevLockHeld
	}
	if err != nil {
		return nil, fmt.Errorf("lock development session: %w", err)
	}
	return lock, nil
}

func removeDevSocket(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (b *devBootstrap) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		close(b.closing)
		err := b.server.Close()
		<-b.done
		b.mu.Lock()
		serveErr := b.serveErr
		b.mu.Unlock()
		b.closeErr = errors.Join(
			err, serveErr, removeDevSocket(b.socket),
			b.lock.Close(),
		)
	})
	return b.closeErr
}

func (b *devBootstrap) Configuration(ctx context.Context) (devConfigurationRequest, error) {
	select {
	case configuration := <-b.configurations:
		return configuration, nil
	case <-b.done:
		b.mu.Lock()
		err := b.serveErr
		b.mu.Unlock()
		if err == nil {
			return devConfigurationRequest{}, failure.Wrap("read development configuration", failure.DevSocketUnavailable, errors.New("development session socket closed before configuration"))
		}
		return devConfigurationRequest{}, failure.Wrap("read development configuration", failure.DevSocketUnavailable, err)
	case <-ctx.Done():
		return devConfigurationRequest{}, ctx.Err()
	}
}

func (b *devBootstrap) Target(ctx context.Context) (devTargetRequest, error) {
	select {
	case result := <-b.targets:
		return result.target, result.err
	case <-b.done:
		b.mu.Lock()
		err := b.serveErr
		b.mu.Unlock()
		if err == nil {
			return devTargetRequest{}, failure.Wrap("read development target", failure.DevSocketUnavailable, errors.New("development session socket closed before target registration"))
		}
		return devTargetRequest{}, failure.Wrap("read development target", failure.DevSocketUnavailable, err)
	case <-ctx.Done():
		return devTargetRequest{}, ctx.Err()
	}
}

func (b *devBootstrap) Resolve(assignment devConfigurationResponse, err error) {
	b.resolveOnce.Do(func() {
		b.mu.Lock()
		b.assignment = assignment
		b.configurationErr = err
		b.mu.Unlock()
		close(b.resolved)
	})
}
