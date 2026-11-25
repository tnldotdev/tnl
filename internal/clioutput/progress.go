package clioutput

import (
	"context"
	"io"
	"os"
	"time"

	"golang.org/x/term"
)

const (
	progressDelay = 300 * time.Millisecond
	progressTick  = 120 * time.Millisecond
	clearLine     = "\r\x1b[K"
)

type noProgressKey struct{}

// WithoutProgress disables progress rendering for the invocation.
func WithoutProgress(ctx context.Context) context.Context {
	return context.WithValue(ctx, noProgressKey{}, true)
}

// StartProgress shows a delayed loader during a quiet human wait. Call the
// returned stop function before writing anything to either stream or returning.
// It joins the renderer and clears its line, even on cancellation.
func StartProgress(ctx context.Context, stdout, stderr io.Writer, human bool, label string) func() {
	if !human || ctx.Err() != nil || ctx.Value(noProgressKey{}) != nil ||
		os.Getenv("CI") != "" || os.Getenv("TERM") == "dumb" ||
		!isTerminal(stdout) || !isTerminal(stderr) {
		return func() {}
	}
	return startProgress(ctx, stderr, label, func() int { return TerminalWidth(stderr, defaultWidth) })
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(int(file.Fd()))
}

func startProgress(ctx context.Context, stderr io.Writer, label string, width func() int) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	label = sanitize(label)
	delay := time.NewTimer(progressDelay)
	go func() {
		defer close(done)
		defer delay.Stop()
		select {
		case <-ctx.Done():
			return
		case <-delay.C:
		}

		visible := false
		defer func() {
			if visible {
				_, _ = io.WriteString(stderr, clearLine)
			}
		}()
		ticker := time.NewTicker(progressTick)
		defer ticker.Stop()
		const frames = "|/-\\"
		for frame := 0; ctx.Err() == nil; frame = (frame + 1) % len(frames) {
			text := progressFrame(label, frames[frame], width())
			if text != "" || visible {
				line := "\r" + text + "\x1b[K"
				n, err := io.WriteString(stderr, line)
				visible = visible || n > 0
				if err != nil || n != len(line) {
					return
				}
				visible = text != ""
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func progressFrame(label string, spinner byte, columns int) string {
	// leave the last column empty so the terminal can't wrap the frame.
	if columns < 2 {
		return ""
	}
	available := columns - 3
	if available < 1 || label == "" {
		return string(spinner)
	}
	if len(label) > available {
		if available > 3 {
			label = label[:available-3] + "..."
		} else {
			label = label[:available]
		}
	}
	return label + " " + string(spinner)
}
