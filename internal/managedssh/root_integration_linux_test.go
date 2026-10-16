package managedssh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/tnldotdev/tnl/internal/testutil"
	"golang.org/x/crypto/ssh"
)

var rootUser = flag.String("tnl-test-managed-ssh-root-user", "", "named user in the disposable managed SSH container")

func productionTestRunner(t *testing.T) *Runner {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &Runner{Executable: exe, Args: []string{"-test.run=^TestChildProcess$", "--", "--managed-ssh-production-child"}}
}

func rootSSHClient(t *testing.T, runner *Runner, recheck time.Duration) (*ssh.Client, <-chan error) {
	t.Helper()
	config := protocolConfig(t)
	config.Users = []string{*rootUser}
	config.Runner = runner
	config.RecheckInterval = recheck
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	address, done := protocolListen(t, server)
	client, err := ssh.Dial("tcp", address, protocolClientConfig(config, *rootUser))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, done
}

func TestIntegrationManagedSSHRoot(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *rootUser == "" {
		t.Skip("requires -tnl-test-managed-ssh-root-user and the disposable container fixture")
	}
	if _, err := os.Stat("/run/tnl-managedssh-fixture"); err != nil {
		t.Fatal("root checks require the isolated managed SSH container")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("container test must start as root")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(status, []byte("NoNewPrivs:\t1")) {
		t.Fatal("container must use --security-opt=no-new-privileges")
	}
	u, err := user.Lookup(*rootUser)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if uid == 0 {
		t.Fatal("fixture user must be non-root")
	}
	groupsBefore, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(t.TempDir(), "root-signing-state")
	if err := os.WriteFile(secretPath, []byte("fixture signing state must never reach a user child"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNLD_STORAGE_KEY", "fixture ambient value must not reach the child")
	runner := productionTestRunner(t)
	t.Run("command credentials and environment", func(t *testing.T) {
		client, done := rootSSHClient(t, runner, time.Second)
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		command := fmt.Sprintf("id -u; id -g; id -G; pwd; printf '%%s\\n' \"${TNLD_STORAGE_KEY-unset}\"; if cat %s 2>/dev/null; then exit 98; fi; grep '^NoNewPrivs:' /proc/self/status", strconv.Quote(secretPath))
		output, err := session.Output(command)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) != 6 || lines[0] != u.Uid || lines[1] != u.Gid || lines[3] != u.HomeDir || lines[4] != "unset" || lines[5] != "NoNewPrivs:\t1" {
			t.Fatalf("child credentials/environment = %q", output)
		}
		expected, err := u.GroupIds()
		if err != nil {
			t.Fatal(err)
		}
		actual := strings.Fields(lines[2])
		slices.Sort(expected)
		slices.Sort(actual)
		if !slices.Equal(actual, expected) || slices.Contains(actual, "0") {
			t.Fatalf("child groups = %v, expected %v", actual, expected)
		}
		client.Close()
		awaitProtocol(t, done)
	})
	t.Run("sftp owns files and cannot read root state", func(t *testing.T) {
		client, done := rootSSHClient(t, runner, time.Second)
		files, err := sftp.NewClient(client)
		if err != nil {
			t.Fatal(err)
		}
		if file, err := files.Open(secretPath); err == nil {
			file.Close()
			t.Fatal("sftp read root signing state")
		}
		path := filepath.Join(u.HomeDir, "root-test-sftp")
		file, err := files.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("owned by the selected account")); err != nil {
			t.Fatal(err)
		}
		file.Close()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != uint32(uid) || stat.Gid != uint32(gid) {
			t.Fatalf("sftp file owner = %d:%d", stat.Uid, stat.Gid)
		}
		files.Close()
		client.Close()
		awaitProtocol(t, done)
	})
	t.Run("forward socket is owned by the selected account", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		accepted := make(chan net.Conn, 1)
		go func() {
			c, err := listener.Accept()
			if err == nil {
				accepted <- c
			}
		}()
		client, done := rootSSHClient(t, runner, time.Second)
		forward, err := client.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer forward.Close()
		remote := awaitProtocol(t, accepted)
		defer remote.Close()
		port := remote.RemoteAddr().(*net.TCPAddr).Port
		table, err := os.ReadFile("/proc/net/tcp")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, line := range strings.Split(string(table), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			_, localPort, _ := strings.Cut(fields[1], ":")
			if localPort == fmt.Sprintf("%04X", port) {
				if fields[7] != u.Uid {
					t.Fatalf("forward socket uid = %s", fields[7])
				}
				found = true
			}
		}
		if !found {
			t.Fatal("outgoing user-owned forwarding socket was not found")
		}
		remote.Close()
		forward.Close()
		client.Close()
		awaitProtocol(t, done)
	})
	t.Run("pty modes and signal", func(t *testing.T) {
		client, done := rootSSHClient(t, runner, time.Second)
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0, ssh.VINTR: 2}); err != nil {
			t.Fatal(err)
		}
		output, err := session.Output("stty -a")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(output, []byte("-echo")) || !bytes.Contains(output, []byte("intr = ^B")) {
			t.Fatalf("pty modes = %s", output)
		}
		session.Close()
		session, err = client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		out, err := session.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := session.Start("printf ready; exec sleep 30"); err != nil {
			t.Fatal(err)
		}
		var ready [5]byte
		if _, err := io.ReadFull(out, ready[:]); err != nil {
			t.Fatal(err)
		}
		if err := session.Signal(ssh.SIGTERM); err != nil {
			t.Fatal(err)
		}
		var exit *ssh.ExitError
		if err := session.Wait(); !errors.As(err, &exit) || exit.Signal() != "TERM" {
			t.Fatalf("root-to-user signal = %v", err)
		}
		client.Close()
		awaitProtocol(t, done)
	})
	t.Run("inherited signing descriptor is closed", func(t *testing.T) {
		configR, configW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer configR.Close()
		defer configW.Close()
		statusR, statusW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer statusR.Close()
		defer statusW.Close()
		control, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer control.Close()
		secret, err := os.Open(secretPath)
		if err != nil {
			t.Fatal(err)
		}
		defer secret.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, runner.Executable, runner.Args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		cmd.ExtraFiles = []*os.File{configR, statusW, control, secret}
		var output bytes.Buffer
		cmd.Stdout = &output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		statusW.Close()
		configR.Close()
		setup := childSetup{Request: Request{Username: *rootUser, Kind: "command", Command: "if (cat <&6) 2>/dev/null; then exit 99; fi; printf clean"}}
		if err := json.NewEncoder(configW).Encode(setup); err != nil {
			t.Fatal(err)
		}
		configW.Close()
		decoder := json.NewDecoder(statusR)
		var ready, finished childStatus
		if err := decoder.Decode(&ready); err != nil || !ready.Ready {
			t.Fatalf("child readiness: %v %#v", err, ready)
		}
		if err := decoder.Decode(&finished); err != nil || finished.ExitCode != 0 || finished.Failed {
			t.Fatalf("child result: %v %#v", err, finished)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
		if output.String() != "clean" {
			t.Fatalf("descriptor leaked signing state: %q", output.String())
		}
	})
	t.Run("uid zero alias rejected", func(t *testing.T) {
		if ValidateUsers([]string{"tnl-ssh-root-alias"}) == nil {
			t.Fatal("UID-0 alias was allowed")
		}
	})
	t.Run("real uid zero is required", func(t *testing.T) {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), exe, "-test.run=^TestManagedSSHRealUIDHelper$", "-tnl-test-managed-ssh-root-user="+*rootUser, "--", "--managed-ssh-realuid-helper")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("real uid requirement: %v %s", err, output)
		}
	})
	t.Run("account removal closes an active connection", func(t *testing.T) {
		client, done := rootSSHClient(t, runner, 10*time.Millisecond)
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if err := session.Start("exec sleep 30"); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.CommandContext(t.Context(), "/usr/sbin/userdel", "--force", *rootUser).CombinedOutput(); err != nil {
			t.Fatalf("remove disposable account: %v %s", err, output)
		}
		awaitProtocol(t, done)
		if _, err := lookupAccount(*rootUser); err == nil {
			t.Fatal("removed account remained valid")
		}
	})
	groupsAfter, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || !slices.Equal(groupsBefore, groupsAfter) {
		t.Fatal("root serving process changed credentials")
	}
	t.Logf("verified uid/gid %d:%d, supplementary groups, NoNewPrivileges, PTY modes/signals, SFTP ownership, forwarding socket uid, fd isolation, root alias/real-uid checks, and account removal; parent remains root", uid, gid)
}

func TestManagedSSHRealUIDHelper(t *testing.T) {
	if os.Args[len(os.Args)-1] != "--managed-ssh-realuid-helper" {
		return
	}
	u, err := user.Lookup(*rootUser)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	if err := syscall.Setresuid(uid, 0, 0); err != nil {
		t.Fatal(err)
	}
	config := protocolConfig(t)
	config.Users = []string{*rootUser}
	if _, err := New(config); !errors.Is(err, ErrConfiguration) {
		t.Fatal("accepted real non-root/effective root credentials")
	}
}
