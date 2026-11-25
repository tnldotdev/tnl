package background

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// ReceiptWriteError marks a failed descriptor write. callers must not retry it
// through an unbounded diagnostic writer, which may share the failed descriptor.
type ReceiptWriteError struct{ err error }

func (e *ReceiptWriteError) Error() string { return "write background receipt: " + e.err.Error() }
func (e *ReceiptWriteError) Unwrap() error { return e.err }

// ReceiptWriter bounds backpressure on pipes and terminal streams during handoff.
// other writers are called directly and must not block beyond the context.
func ReceiptWriter(ctx context.Context, output io.Writer) io.Writer {
	if file, ok := output.(*os.File); ok {
		return receiptFile{ctx: ctx, file: file}
	}
	return output
}

type receiptFile struct {
	ctx  context.Context
	file *os.File
}

// Fd preserves terminal width detection without changing the file's blocking mode.
func (w receiptFile) Fd() uintptr {
	fd := ^uintptr(0)
	if raw, err := w.file.SyscallConn(); err == nil {
		_ = raw.Control(func(current uintptr) { fd = current })
	}
	return fd
}

func (w receiptFile) Write(p []byte) (n int, result error) {
	defer func() {
		if result != nil {
			result = &ReceiptWriteError{err: result}
		}
	}()
	raw, err := w.file.SyscallConn()
	if err != nil {
		return 0, err
	}
	controlErr := raw.Control(func(fd uintptr) {
		n, result = writeReceiptFile(w.ctx, int(fd), p)
	})
	return n, errors.Join(result, controlErr)
}

func writeReceiptFile(ctx context.Context, fd int, p []byte) (int, error) {
	written := 0
	var poll []unix.PollFd
	for written < len(p) {
		if err := context.Cause(ctx); err != nil {
			return written, err
		}
		n, writeErr, restoreErr := tryReceiptWrite(fd, p[written:])
		written += max(0, n)
		if restoreErr != nil {
			return written, errors.Join(writeErr, fmt.Errorf("restore receipt descriptor flags: %w", restoreErr))
		}
		switch {
		case writeErr == nil && n > 0:
			continue
		case writeErr == nil:
			return written, io.ErrShortWrite
		case errors.Is(writeErr, unix.EINTR):
			continue
		case !errors.Is(writeErr, unix.EAGAIN) && !errors.Is(writeErr, unix.EWOULDBLOCK):
			return written, writeErr
		}

		if poll == nil {
			r, w, err := os.Pipe()
			if err != nil {
				return written, err
			}
			wakeDone := make(chan struct{})
			stop := context.AfterFunc(ctx, func() {
				defer close(wakeDone)
				_ = w.Close() // wake the poll with EOF, even if no output can drain
			})
			defer func() {
				if stop() {
					_ = w.Close()
				} else {
					<-wakeDone
				}
				_ = r.Close()
			}()
			poll = []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}, {Fd: int32(r.Fd()), Events: unix.POLLIN}}
		}
		if _, err := unix.Poll(poll, -1); err != nil && !errors.Is(err, unix.EINTR) {
			return written, err
		}
	}
	return written, nil
}

func tryReceiptWrite(fd int, p []byte) (n int, writeErr, restoreErr error) {
	flags, err := receiptFcntl(fd, unix.F_GETFL, 0)
	if err != nil {
		return 0, err, nil
	}
	// nonblocking is shared with aliases of this descriptor. restore it before
	// waiting, rather than leaving it set for the lifetime of the launcher.
	if flags&unix.O_NONBLOCK == 0 {
		if _, err := receiptFcntl(fd, unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
			return 0, err, nil
		}
		defer func() { _, restoreErr = receiptFcntl(fd, unix.F_SETFL, flags) }()
	}
	// os.Stdout.Write and os.Stderr.Write re-raise SIGPIPE instead of returning
	// EPIPE. using the descriptor directly keeps error handling local here.
	n, writeErr = unix.Write(fd, p)
	return n, writeErr, nil
}

func receiptFcntl(fd, command, arg int) (int, error) {
	for {
		n, err := unix.FcntlInt(uintptr(fd), command, arg)
		if !errors.Is(err, unix.EINTR) {
			return n, err
		}
	}
}
