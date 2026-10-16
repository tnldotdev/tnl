package sshclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"golang.org/x/crypto/ssh"
)

// Session contains public connection settings only. certificate issuance and
// private identity material belong to the hidden connect command.
type Session struct {
	Executable      string
	ServerURL       string
	StateDir        string
	PublicURLID     string
	Hostname        string
	User            string
	HostKey         string
	LocalForwards   []string
	DynamicForwards []string
	Command         []string
}

// Run inherits the supplied streams directly, including terminal file handles.
// use real files for interactive sessions; arbitrary blocking readers cannot be
// interrupted by os/exec. cancellation kills ssh and removes temporary trust.
func Run(ctx context.Context, session Session, stdin io.Reader, stdout, stderr io.Writer) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := findOpenSSH()
	if err != nil {
		return err
	}
	session, key, err := validateSession(session)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "tnl-ssh-")
	if err != nil {
		return &Error{Op: "create private SSH trust directory", Err: err}
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			result = errors.Join(result, &Error{Op: "remove private SSH trust directory", Err: err})
		}
	}()
	knownHosts := filepath.Join(dir, "known_hosts")
	entry := hostKeyAlias(session) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + "\n"
	if err := os.WriteFile(knownHosts, []byte(entry), 0o600); err != nil {
		return &Error{Op: "write pinned SSH host key", Err: err}
	}
	cmd := exec.CommandContext(ctx, path, commandArgs(session, knownHosts, key.Type())...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	// let OpenSSH's signal handler close its ProxyCommand child before WaitDelay
	// falls back to killing a stuck client. a separate process group would break
	// foreground terminal ownership for interactive sessions.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code := exit.ExitCode()
			if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				code = 128 + int(status.Signal())
			}
			return &ExitError{Code: code, Err: err}
		}
		return &Error{Op: "start SSH", Err: err}
	}
	return nil
}

// CheckAvailable reports a missing system client before the CLI reads login or
// network state. Run checks again when it starts the actual invocation.
func CheckAvailable() error {
	_, err := findOpenSSH()
	return err
}

func findOpenSSH() (string, error) {
	path, err := exec.LookPath("ssh")
	if err != nil {
		return "", &Error{Op: "find OpenSSH", Err: errors.Join(ErrSSHUnavailable, err)}
	}
	return path, nil
}

// ValidateForwards checks the CLI's bounded TCP-only forwarding surface before
// control requests. normalization still happens at the invocation boundary.
func ValidateForwards(local, dynamic []string) error {
	for _, forward := range local {
		if _, err := normalizeForward(forward, false); err != nil {
			return err
		}
	}
	for _, forward := range dynamic {
		if _, err := normalizeForward(forward, true); err != nil {
			return err
		}
	}
	return nil
}

func validateSession(s Session) (Session, ssh.PublicKey, error) {
	invalid := func() (Session, ssh.PublicKey, error) { return s, nil, ErrInvalidSession }
	if !filepath.IsAbs(s.Executable) || s.StateDir == "" || strings.ContainsAny(s.Executable+s.StateDir, "\x00\r\n") ||
		!opaqueid.Valid(s.PublicURLID, opaqueid.PublicURLPrefix) || !validHostname(s.Hostname) || !validUser(s.User) {
		return invalid()
	}
	u, err := url.Parse(s.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !validHostname(u.Hostname()) {
		return invalid()
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" && !validPort(port) {
		return invalid()
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" && port != "443" {
		host += ":" + port
	}
	s.ServerURL = "https://" + host
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(s.HostKey))
	if err != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return s, nil, errors.Join(ErrInvalidHostKey, err)
	}
	if _, cert := key.(*ssh.Certificate); cert {
		return s, nil, ErrInvalidHostKey
	}
	s.LocalForwards = append([]string(nil), s.LocalForwards...)
	s.DynamicForwards = append([]string(nil), s.DynamicForwards...)
	for i, value := range s.LocalForwards {
		forward, err := normalizeForward(value, false)
		if err != nil {
			return s, nil, err
		}
		s.LocalForwards[i] = forward
	}
	for i, value := range s.DynamicForwards {
		forward, err := normalizeForward(value, true)
		if err != nil {
			return s, nil, err
		}
		s.DynamicForwards[i] = forward
	}
	return s, key, nil
}

func hostKeyAlias(s Session) string {
	return fmt.Sprintf("tnl-ssh-%x", sha256.Sum256([]byte(s.ServerURL+"\x00"+s.PublicURLID)))
}

func commandArgs(s Session, knownHosts, keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		keyType = ssh.KeyAlgoRSASHA512 + "," + ssh.KeyAlgoRSASHA256
	}
	proxy := []string{s.Executable, "ssh", "connect", "--server", s.ServerURL, "--state-dir", s.StateDir, "--public-url-id", s.PublicURLID}
	for i := range proxy {
		// OpenSSH expands percent tokens before invoking the shell.
		proxy[i] = shellQuote(strings.ReplaceAll(proxy[i], "%", "%%"))
	}
	args := []string{"-F", "none"}
	options := []string{
		"ProxyCommand=" + strings.Join(proxy, " "), "ProxyUseFdpass=no",
		"HostKeyAlias=" + hostKeyAlias(s), "HostKeyAlgorithms=" + keyType,
		"UserKnownHostsFile=" + configQuote(knownHosts), "GlobalKnownHostsFile=/dev/null",
		"StrictHostKeyChecking=yes", "CheckHostIP=no", "UpdateHostKeys=no", "VerifyHostKeyDNS=no", "KnownHostsCommand=none",
		"CanonicalizeHostname=no", "ControlMaster=no", "ControlPath=none", "ControlPersist=no",
		"BatchMode=yes", "PreferredAuthentications=none", "PasswordAuthentication=no", "PubkeyAuthentication=no",
		"KbdInteractiveAuthentication=no", "HostbasedAuthentication=no", "GSSAPIAuthentication=no",
		"NumberOfPasswordPrompts=0", "IdentityFile=none", "CertificateFile=none", "IdentityAgent=none", "IdentitiesOnly=yes",
		"ForwardAgent=no", "AddKeysToAgent=no", "ForwardX11=no", "ForwardX11Trusted=no",
		"GatewayPorts=no", "ExitOnForwardFailure=yes", "PermitRemoteOpen=none", "EscapeChar=none", "EnableEscapeCommandline=no",
	}
	for _, option := range options {
		args = append(args, "-o", option)
	}
	for _, forward := range s.LocalForwards {
		args = append(args, "-L", forward)
	}
	for _, forward := range s.DynamicForwards {
		args = append(args, "-D", forward)
	}
	args = append(args, "-l", s.User, "--", s.Hostname)
	return append(args, s.Command...)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func configQuote(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "\\", "\\\\")
	return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
}

func validUser(s string) bool {
	if s == "" || len(s) > 256 || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func validHostname(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validPort(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	p, err := strconv.Atoi(s)
	return err == nil && p > 0 && p <= 65535
}

func normalizeForward(value string, dynamic bool) (string, error) {
	// brackets protect IPv6 colons; unbracketed colons separate fields.
	var fields []string
	start, bracket := 0, false
	for i, c := range value {
		switch c {
		case '[':
			if bracket || i != start {
				return "", ErrInvalidForward
			}
			bracket = true
		case ']':
			if !bracket || (i+1 < len(value) && value[i+1] != ':') {
				return "", ErrInvalidForward
			}
			bracket = false
		case ':':
			if !bracket {
				fields = append(fields, value[start:i])
				start = i + 1
			}
		}
	}
	if bracket {
		return "", ErrInvalidForward
	}
	fields = append(fields, value[start:])
	want := 3
	if dynamic {
		want = 1
	}
	bind := "127.0.0.1"
	if len(fields) == want+1 {
		bind, fields = strings.TrimSuffix(strings.TrimPrefix(fields[0], "["), "]"), fields[1:]
	}
	if len(fields) != want || !validPort(fields[0]) {
		return "", ErrInvalidForward
	}
	if bind == "localhost" {
		bind = "127.0.0.1"
	}
	ip := net.ParseIP(bind)
	if ip == nil || !ip.IsLoopback() {
		return "", ErrInvalidForward
	}
	result := net.JoinHostPort(ip.String(), fields[0])
	if !dynamic {
		host := strings.TrimSuffix(strings.TrimPrefix(fields[1], "["), "]")
		if !validHostname(host) || !validPort(fields[2]) {
			return "", ErrInvalidForward
		}
		result += ":" + net.JoinHostPort(host, fields[2])
	}
	return result, nil
}
