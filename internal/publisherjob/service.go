package publisherjob

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Commands is injectable so adapter tests never touch a system service manager.
type Commands func(context.Context, string, ...string) error

func systemCommand(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

// Install copies the running binary into system-owned job state, then installs
// the platform service. No enrollment key or signing key appears in its arguments.
func Install(ctx context.Context, store *Store) error {
	if os.Geteuid() != 0 {
		return errors.New("installing the publisher service requires root")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	from, err := os.Open(executable)
	if err != nil {
		return err
	}
	defer from.Close()
	staged, err := os.CreateTemp(store.root, ".tnl-publisher-*")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	defer staged.Close()
	if err := staged.Chmod(0o700); err != nil {
		return err
	}
	if _, err := io.Copy(staged, from); err != nil {
		return err
	}
	if err := staged.Sync(); err != nil {
		return err
	}
	if err := os.Rename(staged.Name(), filepath.Join(store.root, "tnl-publisher")); err != nil {
		return err
	}
	return installService(ctx, runtime.GOOS, store.root, "", systemCommand)
}

func installService(ctx context.Context, platform, root, unitPath string, run Commands) error {
	bin := filepath.Join(root, "tnl-publisher")
	switch platform {
	case "darwin":
		path := "/Library/LaunchDaemons/dev.tnl.pub.plist"
		if unitPath != "" {
			path = unitPath
		}
		body := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>dev.tnl.pub</string><key>ProgramArguments</key><array><string>` + html.EscapeString(bin) + `</string><string>publisher</string><string>service</string><string>run</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>
`
		if err := writeUnit(path, body); err != nil {
			return err
		}
		if err := run(ctx, "launchctl", "print", "system/dev.tnl.pub"); err == nil {
			return run(ctx, "launchctl", "kickstart", "-k", "system/dev.tnl.pub")
		}
		return run(ctx, "launchctl", "bootstrap", "system", path)
	case "linux":
		path := "/etc/systemd/system/tnl-publisher.service"
		if unitPath != "" {
			path = unitPath
		}
		// systemd paths may contain spaces; quote the executable independently.
		body := "[Unit]\nDescription=tnl enrolled publisher\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nUMask=0077\nExecStart=\"" + strings.ReplaceAll(bin, `"`, `\"`) + "\" publisher service run\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
		if err := writeUnit(path, body); err != nil {
			return err
		}
		for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "tnl-publisher.service"}, {"restart", "tnl-publisher.service"}} {
			if err := run(ctx, "systemctl", args...); err != nil {
				return fmt.Errorf("systemctl %s: %w", args[0], err)
			}
		}
		return nil
	default:
		return errors.New("system publisher jobs require macOS or Linux")
	}
}

func writeUnit(path, body string) error {
	// a root-owned system unit must never be redirected through a symlink.
	if info, err := os.Lstat(path); err == nil {
		if checkOwner(info, 0, false) != nil {
			return errors.New("service unit is not a root-owned regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staged, err := os.CreateTemp(filepath.Dir(path), ".tnl-publisher-*")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	defer staged.Close()
	if err := staged.Chmod(0o600); err != nil {
		return err
	}
	if _, err := io.WriteString(staged, body); err != nil {
		return err
	}
	if err := staged.Sync(); err != nil {
		return err
	}
	return os.Rename(staged.Name(), path)
}
