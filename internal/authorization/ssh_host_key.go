package authorization

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHHostKeyValid checks one plain Ed25519 public host key in authorized-key format.
func SSHHostKeyValid(value string) bool {
	line := strings.TrimSpace(value)
	if len(value) > 1024 || strings.ContainsAny(line, "\x00\r\n") || !strings.HasPrefix(line, ssh.KeyAlgoED25519+" ") && !strings.HasPrefix(line, ssh.KeyAlgoED25519+"\t") {
		return false
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	return err == nil && key.Type() == ssh.KeyAlgoED25519 && len(options) == 0 && len(strings.TrimSpace(string(rest))) == 0
}
