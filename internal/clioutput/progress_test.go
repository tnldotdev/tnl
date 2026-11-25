package clioutput

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestProgressFinishesBeforeDelayWithoutWriting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var stderr bytes.Buffer
		stop := startProgress(t.Context(), &stderr, "Checking accounts", func() int { return 80 })
		time.Sleep(progressDelay - time.Millisecond)
		stop()
		time.Sleep(progressDelay + progressTick)
		if got := stderr.String(); got != "" {
			t.Fatalf("fast wait wrote %q", got)
		}
	})
}

func TestProgressClearsBeforeNextOutput(t *testing.T) {
	for _, byCancel := range []bool{false, true} {
		name := "explicit stop"
		if byCancel {
			name = "context cancellation"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lines := make(chan string, 5)
				writer := progressWriter(func(p []byte) (int, error) {
					lines <- string(p)
					return len(p), nil
				})
				next := func() string {
					t.Helper()
					synctest.Wait()
					select {
					case line := <-lines:
						return line
					default:
						t.Fatal("missing progress output")
						return ""
					}
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				stop := startProgress(ctx, writer, "Checking accounts", func() int { return 80 })
				defer stop()
				time.Sleep(progressDelay)
				if got := next(); got != "\rChecking accounts |\x1b[K" {
					t.Fatalf("first progress frame = %q", got)
				}
				time.Sleep(progressTick)
				if got := next(); got != "\rChecking accounts /\x1b[K" {
					t.Fatalf("second progress frame = %q", got)
				}
				if byCancel {
					cancel()
				} else {
					stop()
				}
				if got := next(); got != clearLine {
					t.Fatalf("progress did not clear: %q", got)
				}
				stop()
				time.Sleep(progressTick)
				select {
				case got := <-lines:
					t.Fatalf("renderer wrote again after stop: %q", got)
				default:
				}
			})
		})
	}
}

func TestProgressClearsAfterPartialWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts []string
		writer := progressWriter(func(p []byte) (int, error) {
			attempts = append(attempts, string(p))
			if len(attempts) == 1 {
				return 2, io.ErrShortWrite
			}
			return len(p), nil
		})
		stop := startProgress(t.Context(), writer, "Checking accounts", func() int { return 80 })
		time.Sleep(progressDelay + progressTick)
		stop()
		if len(attempts) != 2 || attempts[1] != clearLine {
			t.Fatalf("progress writes = %q", attempts)
		}
	})
}

type progressWriter func([]byte) (int, error)

func (w progressWriter) Write(p []byte) (int, error) { return w(p) }

func TestProgressFitsOneLineAndEscapesLabels(t *testing.T) {
	label := sanitize("Checking accounts\n\x1b[31m")
	if !strings.Contains(progressFrame(label, '|', 80), `accounts\x0a\x1b[31m`) {
		t.Fatal("progress label lost escaping")
	}
	for columns := 1; columns < 80; columns++ {
		if got := progressFrame(label, '|', columns); len(got) >= columns {
			t.Fatalf("%d columns: frame would wrap: %q", columns, got)
		}
	}
}
