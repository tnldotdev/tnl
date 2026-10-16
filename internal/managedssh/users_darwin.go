package managedssh

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func platformShell(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+name, "UserShell")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if out, err := cmd.Output(); err == nil {
		if shell, ok := strings.CutPrefix(strings.TrimSpace(string(out)), "UserShell: "); ok && strings.HasPrefix(shell, "/") && !strings.ContainsAny(shell, "\x00\r\n") {
			return shell
		}
	}
	return "/bin/sh"
}
