package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testSession(t *testing.T) Session {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return Session{Executable: "/absolute/tnl", ServerURL: "https://CONTROL.example:443/", StateDir: "/state", PublicURLID: "url_0123456789ABCDEFGHIJKL", Hostname: "ssh.example", User: "developer", HostKey: string(ssh.MarshalAuthorizedKey(key))}
}

func TestSessionValidation(t *testing.T) {
	base := testSession(t)
	for name, mutate := range map[string]func(*Session){
		"relative executable": func(s *Session) { s.Executable = "tnl" },
		"bad id":              func(s *Session) { s.PublicURLID += "%h" },
		"legacy id":           func(s *Session) { s.PublicURLID = "public_url_0123456789ABCDEFGHIJKL" },
		"host option":         func(s *Session) { s.Hostname = "-oProxyCommand=evil" },
		"user newline":        func(s *Session) { s.User = "name\nProxyCommand=evil" },
		"http":                func(s *Session) { s.ServerURL = "http://control.example" },
		"url credentials":     func(s *Session) { s.ServerURL = "https://secret@control.example" },
		"url query":           func(s *Session) { s.ServerURL = "https://control.example?token=secret" },
		"public listener":     func(s *Session) { s.LocalForwards = []string{"0.0.0.0:8080:localhost:80"} },
	} {
		t.Run(name, func(t *testing.T) {
			s := base
			mutate(&s)
			if _, _, err := validateSession(s); err == nil {
				t.Fatal("accepted invalid session")
			}
		})
	}
	for _, key := range []string{"bad key", "restrict " + base.HostKey, base.HostKey + base.HostKey} {
		s := base
		s.HostKey = key
		if _, _, err := validateSession(s); !errors.Is(err, ErrInvalidHostKey) {
			t.Fatalf("host key error = %v", err)
		}
	}
	a, _, err := validateSession(base)
	if err != nil {
		t.Fatal(err)
	}
	if a.ServerURL != "https://control.example" {
		t.Fatal(a.ServerURL)
	}
	b := a
	b.ServerURL += ":8443"
	if hostKeyAlias(a) == hostKeyAlias(b) {
		t.Fatal("alias did not bind control URL")
	}
	b = a
	b.PublicURLID = "url_1123456789ABCDEFGHIJKL"
	if hostKeyAlias(a) == hostKeyAlias(b) {
		t.Fatal("alias did not bind public URL ID")
	}
}

func TestForwards(t *testing.T) {
	for _, tc := range []struct {
		value, want string
		dynamic     bool
	}{
		{"8080:localhost:80", "127.0.0.1:8080:localhost:80", false},
		{"localhost:8080:db.example:5432", "127.0.0.1:8080:db.example:5432", false},
		{"[::1]:8080:[::1]:80", "[::1]:8080:[::1]:80", false},
		{"1080", "127.0.0.1:1080", true},
		{"[::1]:1080", "[::1]:1080", true},
	} {
		got, err := normalizeForward(tc.value, tc.dynamic)
		if err != nil || got != tc.want {
			t.Fatalf("%q => %q, %v", tc.value, got, err)
		}
	}
	for _, value := range []string{"*:8080:host:80", ":8080:host:80", "0.0.0.0:8080:host:80", "[::]:8080:host:80", "example.com:8080:host:80", "/tmp/sock:host:80", "8080:/tmp/sock", "8080:host:0", "0:host:80", "65536:host:80", "8080:bad%h:80", "[::1:8080:host:80", "8080:[::1]]:80"} {
		if _, err := normalizeForward(value, false); !errors.Is(err, ErrInvalidForward) {
			t.Errorf("accepted %q: %v", value, err)
		}
	}
	for _, value := range []string{"*:1080", "0.0.0.0:1080", "/tmp/socket", "1080:host:80", "0"} {
		if _, err := normalizeForward(value, true); !errors.Is(err, ErrInvalidForward) {
			t.Errorf("accepted dynamic %q: %v", value, err)
		}
	}
}

func TestProxyShellQuoting(t *testing.T) {
	s := testSession(t)
	s.Executable = "/absolute/tnl's $path; %h"
	s.StateDir = "/state/'quoted' $(touch nope); %n %%"
	args := commandArgs(s, "/private/file", ssh.KeyAlgoED25519)
	var proxy string
	for _, arg := range args {
		if strings.HasPrefix(arg, "ProxyCommand=") {
			proxy = strings.TrimPrefix(arg, "ProxyCommand=")
		}
	}
	// model OpenSSH's %% expansion, then execute the actual shell parser.
	proxy = strings.ReplaceAll(proxy, "%%", "%")
	proxy = "set -- " + proxy + "; printf '%s\\000' \"$@\""
	out, err := exec.Command("/bin/sh", "-c", proxy).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{s.Executable, "ssh", "connect", "--server", s.ServerURL, "--state-dir", s.StateDir, "--public-url-id", s.PublicURLID}
	got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("proxy argv = %#v; want %#v", got, want)
	}
	joined := strings.Join(args, "\n")
	for _, required := range []string{"StrictHostKeyChecking=yes", "PreferredAuthentications=none", "ForwardAgent=no", "EscapeChar=none", "ControlPath=none"} {
		if !strings.Contains(joined, required) {
			t.Errorf("missing %s", required)
		}
	}
	if args[0] != "-F" || args[1] != "none" {
		t.Fatal("ssh config was not disabled")
	}
}

func fakeSSH(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestRunStreamsExitAndCleanup(t *testing.T) {
	record := filepath.Join(t.TempDir(), "record")
	fakeSSH(t, "record="+shellQuote(record)+"\n"+`for arg do
case "$arg" in
UserKnownHostsFile=*) file=${arg#UserKnownHostsFile=}; file=${file#\"}; file=${file%\"}; printf '%s' "$file" > "$record"; /bin/cat "$file" > "$record.key";;
esac
done
/bin/cat
printf 'diagnostic' >&2
exit 23
`)
	s := testSession(t)
	var stdout, stderr bytes.Buffer
	err := Run(t.Context(), s, strings.NewReader("input"), &stdout, &stderr)
	var exit *ExitError
	var process *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 || !errors.As(err, &process) {
		t.Fatalf("exit error = %v", err)
	}
	if stdout.String() != "input" || stderr.String() != "diagnostic" {
		t.Fatalf("streams = %q / %q", &stdout, &stderr)
	}
	path, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(string(path))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary trust remained: %v", err)
	}
	key, err := os.ReadFile(record + ".key")
	if err != nil {
		t.Fatal(err)
	}
	normalized, _, _ := validateSession(s)
	if string(key) != hostKeyAlias(normalized)+" "+s.HostKey {
		t.Fatalf("wrong pinned trust: %q", key)
	}
}

func TestRunMissingSSH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	err := Run(t.Context(), testSession(t), nil, nil, nil)
	var owned *Error
	if !errors.Is(err, ErrSSHUnavailable) || !errors.As(err, &owned) {
		t.Fatal(err)
	}
}

func TestRunCancellationCleansTrust(t *testing.T) {
	record := filepath.Join(t.TempDir(), "record")
	fakeSSH(t, "record="+shellQuote(record)+"\n"+`for arg do
case "$arg" in
UserKnownHostsFile=*) file=${arg#UserKnownHostsFile=}; file=${file#\"}; file=${file%\"}; printf '%s' "$file" > "$record";;
esac
done
while :; do :; done
`)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	s := testSession(t)
	go func() { done <- Run(ctx, s, nil, nil, nil) }()
	var path []byte
	for len(path) == 0 && ctx.Err() == nil {
		path, _ = os.ReadFile(record)
		time.Sleep(time.Millisecond)
	}
	if len(path) == 0 {
		t.Fatal("ssh did not start")
	}
	for file, mode := range map[string]os.FileMode{string(path): 0o600, filepath.Dir(string(path)): 0o700} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("private trust permissions: %v, %v", info, err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ssh cancellation blocked")
	}
	if _, err := os.Stat(filepath.Dir(string(path))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary trust remained: %v", err)
	}
}

// stdioConn is only a subprocess fixture; production uses system OpenSSH.
type stdioConn struct{}

func (stdioConn) Read(p []byte) (int, error)       { return os.Stdin.Read(p) }
func (stdioConn) Write(p []byte) (int, error)      { return os.Stdout.Write(p) }
func (stdioConn) Close() error                     { return nil }
func (stdioConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (stdioConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (stdioConn) SetDeadline(time.Time) error      { return nil }
func (stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (stdioConn) SetWriteDeadline(time.Time) error { return nil }

func fixtureSigner(t *testing.T) ssh.Signer {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

var (
	sshClientTestHelper = flag.Bool("tnl-ssh-client-helper", false, "run the private SSH subprocess fixture")
	sshClientReadyFile  = flag.String("tnl-ssh-client-ready-file", "", "record the waiting SSH fixture pid")
)

func TestOpenSSHHelper(t *testing.T) {
	if !*sshClientTestHelper {
		return
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(fixtureSigner(t))
	conn, channels, requests, err := ssh.NewServerConn(stdioConn{}, config)
	if err != nil {
		os.Exit(1)
	}
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		channel, requests, err := incoming.Accept()
		if err != nil {
			os.Exit(1)
		}
		for request := range requests {
			if request.Type == "exec" {
				_ = request.Reply(true, nil)
				if *sshClientReadyFile != "" {
					if err := os.WriteFile(*sshClientReadyFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
						os.Exit(1)
					}
					for range requests {
					}
					os.Exit(0)
				}
				_, _ = io.WriteString(channel, "managed session\n")
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{37}))
				_ = channel.Close()
				_ = conn.Close()
				os.Exit(0)
			}
			_ = request.Reply(false, nil)
		}
	}
	os.Exit(1)
}

func TestSystemOpenSSHManagedSession(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("system OpenSSH is unavailable")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	for _, correctPin := range []bool{true, false} {
		t.Run(fmt.Sprintf("correct_pin=%t", correctPin), func(t *testing.T) {
			s := testSession(t)
			s.Executable = filepath.Join(dir, "tnl's %h helper")
			s.StateDir = filepath.Join(dir, "state's %n $(false)")
			s.Command = []string{"true"}
			if correctPin {
				s.HostKey = string(ssh.MarshalAuthorizedKey(fixtureSigner(t).PublicKey()))
			}
			script := "#!/bin/sh\nprintf '%s\\000' \"$@\" > " + shellQuote(argsFile) + "\nexec " + shellQuote(binary) + " '-test.run=^TestOpenSSHHelper$' -tnl-ssh-client-helper\n"
			if err := os.WriteFile(s.Executable, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			err := Run(ctx, s, strings.NewReader(""), &stdout, &stderr)
			var exit *ExitError
			want := 255
			if correctPin {
				want = 37
			}
			if !errors.As(err, &exit) || exit.ExitCode() != want {
				t.Fatalf("ssh result = %v; stderr = %s", err, &stderr)
			}
			if correctPin && stdout.String() != "managed session\n" || !correctPin && stdout.Len() != 0 {
				t.Fatalf("unexpected session output %q", &stdout)
			}
			argv, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatal(err)
			}
			normalized, _, _ := validateSession(s)
			wantArgv := []string{"ssh", "connect", "--server", normalized.ServerURL, "--state-dir", s.StateDir, "--public-url-id", s.PublicURLID}
			if string(argv) != strings.Join(wantArgv, "\x00")+"\x00" {
				t.Fatalf("helper argv = %q; want %#v", argv, wantArgv)
			}
		})
	}
}

func TestRunCancellationStopsProxyHelper(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("system OpenSSH is unavailable")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	s := testSession(t)
	s.Executable = filepath.Join(dir, "helper")
	s.HostKey = string(ssh.MarshalAuthorizedKey(fixtureSigner(t).PublicKey()))
	s.Command = []string{"wait"}
	script := "#!/bin/sh\nexec " + shellQuote(binary) + " '-test.run=^TestOpenSSHHelper$' -tnl-ssh-client-helper -tnl-ssh-client-ready-file " + shellQuote(ready) + "\n"
	if err := os.WriteFile(s.Executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s, strings.NewReader(""), io.Discard, io.Discard) }()
	var pid int
	for ctx.Err() == nil {
		data, _ := os.ReadFile(ready)
		if pid, _ = strconv.Atoi(string(data)); pid > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if pid <= 0 {
		t.Fatal("proxy fixture did not become ready")
	}
	proxyRunning := true
	t.Cleanup(func() {
		if proxyRunning {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSH cancellation blocked")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			proxyRunning = false
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("SSH left its ProxyCommand helper running")
}
