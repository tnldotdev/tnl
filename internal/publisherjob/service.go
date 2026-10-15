package publisherjob

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/filelock"
)

const ServiceLabel = "dev.tnl.publisher"
const SystemdUnit = "tnl-publisher.service"

var ErrServiceNotLoaded = errors.New("system publisher service is not loaded")

type Command struct {
	Program string
	Args    []string
}
type Executor interface {
	Execute(context.Context, Command) error
}
type ExecutorFunc func(context.Context, Command) error

func (f ExecutorFunc) Execute(ctx context.Context, command Command) error { return f(ctx, command) }

// HostExecutor never captures or forwards external command output into logs.
type HostExecutor struct{}

func (HostExecutor) Execute(ctx context.Context, command Command) error {
	err := exec.CommandContext(ctx, command.Program, command.Args...).Run()
	var exit *exec.ExitError
	if command.Program == "/bin/launchctl" && len(command.Args) > 0 && command.Args[0] == "print" && errors.As(err, &exit) && exit.ExitCode() == 113 {
		return ErrServiceNotLoaded
	}
	return err
}

type ServiceOptions struct {
	Platform     string
	Root         string
	BinarySource string
	// unit directory and owner overrides exist for isolated service tests.
	TestUnitDir  string
	TestOwnerUID *int
}

func DefaultRoot(platform string) string {
	if platform == "darwin" {
		return "/Library/Application Support/tnl/publisher"
	}
	return "/var/lib/tnl/publisher"
}

func (o ServiceOptions) resolved() (ServiceOptions, int, string, error) {
	if o.Platform == "" {
		o.Platform = runtime.GOOS
	}
	if o.Platform != "darwin" && o.Platform != "linux" {
		return o, 0, "", ErrScope
	}
	if o.Root == "" {
		o.Root = DefaultRoot(o.Platform)
	}
	owner := 0
	if o.TestOwnerUID != nil {
		owner = *o.TestOwnerUID
	}
	if owner < 0 || os.Geteuid() != owner || !safeServicePath(o.Root) {
		return o, owner, "", ErrUnsafeState
	}
	dir := "/etc/systemd/system"
	if o.Platform == "darwin" {
		dir = "/Library/LaunchDaemons"
	}
	if o.TestUnitDir != "" {
		if o.TestOwnerUID == nil || !safeServicePath(o.TestUnitDir) {
			return o, owner, "", ErrUnsafeState
		}
		dir = o.TestUnitDir
	}
	return o, owner, dir, nil
}

func safeServicePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n\t%\\")
}

// ServiceUnit contains only the stable binary and private state directory.
// system services run at boot with no login session or secret command arguments.
func ServiceUnit(platform, binary, root string) ([]byte, error) {
	if !safeServicePath(binary) || !safeServicePath(root) {
		return nil, ErrScope
	}
	if platform == "darwin" {
		var body strings.Builder
		body.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>" + ServiceLabel + "</string>\n<key>ProgramArguments</key><array>")
		for _, arg := range []string{binary, "service", "serve", "--system-state-dir", root} {
			body.WriteString("<string>")
			if err := xml.EscapeText(&body, []byte(arg)); err != nil {
				return nil, err
			}
			body.WriteString("</string>")
		}
		body.WriteString("</array>\n<key>UserName</key><string>root</string>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>5</integer>\n<key>ExitTimeOut</key><integer>45</integer>\n<key>Umask</key><integer>63</integer>\n</dict></plist>\n")
		return []byte(body.String()), nil
	}
	if platform != "linux" {
		return nil, ErrScope
	}
	quote := func(value string) string { return strconv.Quote(strings.ReplaceAll(value, "$", "$$")) }
	return []byte("[Unit]\nDescription=tnl enrolled system publications\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nUser=root\nUMask=0077\nExecStart=" + quote(binary) + " service serve --system-state-dir " + quote(root) + "\nRestart=always\nRestartSec=5\nTimeoutStopSec=45\nKillMode=mixed\nNoNewPrivileges=true\nStandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=multi-user.target\n"), nil
}

// InstallService atomically refreshes the running binary before restarting the
// system service. executor injection keeps tests away from the host manager.
func InstallService(ctx context.Context, options ServiceOptions, executor Executor) error {
	o, owner, unitDir, err := options.resolved()
	if err != nil {
		return err
	}
	if executor == nil {
		return ErrScope
	}
	registry, err := Open(ctx, OpenOptions{Root: o.Root, TestOwnerUID: o.TestOwnerUID})
	if err != nil {
		return err
	}
	defer registry.Close()
	// installers serialize separately. service-manager restart must not hold the
	// registry lock needed by the old process's final drain observations.
	installLock, err := filelock.AcquireContext(ctx, filepath.Join(registry.Root(), "install.lock"), owner)
	if err != nil {
		return err
	}
	defer installLock.Close()
	var unitPath string
	err = registry.locked(ctx, func() error {
		binDir := filepath.Join(registry.Root(), "bin")
		if err := ensureServiceDir(binDir, owner, true); err != nil {
			return err
		}
		if err := ensureServiceDir(unitDir, owner, false); err != nil {
			return err
		}
		binary := filepath.Join(binDir, "tnl")
		source, err := os.Open(o.BinarySource)
		if err != nil {
			return failure.Wrap("read service binary", failure.ClientStateUnavailable, err)
		}
		defer source.Close()
		info, err := source.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return ErrUnsafeState
		}
		if err := atomicFile(binary, source, owner, 0o700); err != nil {
			return err
		}
		unit, err := ServiceUnit(o.Platform, binary, registry.Root())
		if err != nil {
			return err
		}
		name := SystemdUnit
		if o.Platform == "darwin" {
			name = ServiceLabel + ".plist"
		}
		unitPath = filepath.Join(unitDir, name)
		if err := atomicFile(unitPath, strings.NewReader(string(unit)), owner, 0o644); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	if o.Platform == "linux" {
		return executeAll(ctx, executor,
			Command{Program: "/bin/systemctl", Args: []string{"daemon-reload"}},
			Command{Program: "/bin/systemctl", Args: []string{"enable", SystemdUnit}},
			Command{Program: "/bin/systemctl", Args: []string{"restart", SystemdUnit}})
	}
	err = executor.Execute(ctx, Command{Program: "/bin/launchctl", Args: []string{"print", "system/" + ServiceLabel}})
	if err == nil {
		if err := executeAll(ctx, executor, Command{Program: "/bin/launchctl", Args: []string{"bootout", "system/" + ServiceLabel}}); err != nil {
			return err
		}
	} else if !errors.Is(err, ErrServiceNotLoaded) {
		return failure.Wrap("inspect system publisher service", failure.ClientStateUnavailable, err)
	}
	return executeAll(ctx, executor, Command{Program: "/bin/launchctl", Args: []string{"bootstrap", "system", unitPath}})
}

func StartService(ctx context.Context, options ServiceOptions, executor Executor) error {
	o, _, _, err := options.resolved()
	if err != nil {
		return err
	}
	if executor == nil {
		return ErrScope
	}
	if o.Platform == "darwin" {
		return executeAll(ctx, executor, Command{Program: "/bin/launchctl", Args: []string{"kickstart", "system/" + ServiceLabel}})
	}
	return executeAll(ctx, executor, Command{Program: "/bin/systemctl", Args: []string{"start", SystemdUnit}})
}

func executeAll(ctx context.Context, executor Executor, commands ...Command) error {
	for _, command := range commands {
		if err := executor.Execute(ctx, command); err != nil {
			return failure.Wrap("manage system publisher service", failure.ClientStateUnavailable, err)
		}
	}
	return nil
}

func ensureServiceDir(path string, owner int, private bool) error {
	canonicalParent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || canonicalParent != filepath.Dir(path) {
		return ErrUnsafeState
	}
	if err := trustedAncestors(canonicalParent, owner); err != nil {
		return err
	}
	mode := os.FileMode(0o755)
	if private {
		mode = 0o700
	}
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ErrUnsafeState
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(owner) || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || private && info.Mode().Perm() != mode {
		return ErrUnsafeState
	}
	return nil
}

func atomicFile(path string, source io.Reader, owner int, mode os.FileMode) error {
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeState
	}
	if err := trustedAncestors(parent, owner); err != nil {
		return err
	}
	previous, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		stat, ok := previous.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(owner) || !previous.Mode().IsRegular() || previous.Mode().Perm() != mode {
			return ErrUnsafeState
		}
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".tnl-install-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	_, copyErr := io.Copy(temp, source)
	err = errors.Join(copyErr, temp.Chmod(mode), temp.Sync(), temp.Close())
	if err != nil {
		return err
	}
	currentParent, err := os.Lstat(parent)
	if err != nil || !os.SameFile(parentInfo, currentParent) {
		return ErrUnsafeState
	}
	if err := trustedAncestors(parent, owner); err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if previous == nil {
		if !errors.Is(err, os.ErrNotExist) {
			return ErrUnsafeState
		}
	} else if err != nil || !os.SameFile(previous, current) || current.Mode() != previous.Mode() {
		return ErrUnsafeState
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return fmt.Errorf("replace system service file: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
