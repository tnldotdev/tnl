package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
)

type loginDesktopActions struct {
	openURL  func(context.Context, string) error
	copyCode func(context.Context, string) error
}

func (actions loginDesktopActions) run(ctx context.Context, op clientstate.AuthOperation, mode statusOutputMode, diagnostics io.Writer) error {
	// keep helper failures and their output out of the machine stream. the
	// printed approval details remain usable if either action fails.
	attempt := func(run func(context.Context, string) error, value, warning string) error {
		if run == nil || value == "" || ctx.Err() != nil || !loginNeedsApproval(op) {
			return nil
		}
		if err := run(ctx, value); err != nil && ctx.Err() == nil && mode != statusOutputJSON {
			return writeResult(diagnostics, clioutput.Text(warning))
		}
		return nil
	}
	if err := attempt(actions.copyCode, op.UserCode, "Could not copy the approval code. Use the printed code."); err != nil {
		return err
	}
	return attempt(actions.openURL, op.ApprovalURL, "Could not open a browser. Visit the printed URL.")
}

func openLoginApprovalURL(_ context.Context, approvalURL string) error {
	// the browser can outlive the login command.
	return openBrowser(approvalURL)
}

func copyLoginApprovalCode(ctx context.Context, code string) error {
	switch runtime.GOOS {
	case "darwin":
		return writeLoginClipboard(ctx, code, "pbcopy")
	case "linux":
		if os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("WAYLAND_SOCKET") != "" {
			err := writeLoginClipboard(ctx, code, "wl-copy", "--type", "text/plain")
			if err == nil || os.Getenv("DISPLAY") == "" || ctx.Err() != nil {
				return err
			}
		}
		if os.Getenv("DISPLAY") != "" {
			return writeLoginClipboard(ctx, code, "xclip", "-selection", "clipboard", "-in")
		}
	}
	return errors.New("no local clipboard available")
}

func writeLoginClipboard(ctx context.Context, code, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(code)
	return cmd.Run()
}
