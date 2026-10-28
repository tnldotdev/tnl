// Package streamcopy copies bytes in both directions and preserves half-closes.
package streamcopy

import (
	"errors"
	"io"
	"net"
	"sync"
)

const bufferSize = 32 << 10

var buffers = sync.Pool{New: func() any {
	buffer := make([]byte, bufferSize)
	return &buffer
}}

type Result struct {
	LeftToRight int64
	RightToLeft int64
}

// Copy waits for both directions and half-closes each destination when supported.
// the caller must close or set deadlines on the connections to cancel the copy.
// a copy or supported half-close failure closes both connections and retains
// both copy causes and cleanup failures.
func Copy(left, right net.Conn) (Result, error) {
	return CopyObserved(left, right, nil, nil)
}

// CopyObserved is Copy with a callback after each write. the callbacks may run
// at the same time and must return quickly.
func CopyObserved(
	left, right net.Conn,
	onLeftToRight, onRightToLeft func(int64),
) (Result, error) {
	type copyResult struct {
		leftToRight bool
		bytes       int64
		err         error
	}
	results := make(chan copyResult, 2)
	copyDirection := func(destination, source net.Conn, leftToRight bool, observe func(int64)) {
		buffer := buffers.Get().(*[]byte)
		writer := io.Writer(destination)
		if observe != nil {
			writer = observedWriter{Writer: destination, observe: observe}
		}
		count, err := io.CopyBuffer(writer, source, *buffer)
		buffers.Put(buffer)
		// io.Copy consumes a clean io.EOF. a non-nil error that wraps EOF can
		// also carry a session reset; it is not permission to keep copying.
		if closer, ok := destination.(interface{ CloseWrite() error }); err == nil && ok {
			err = closer.CloseWrite()
			if err == errors.ErrUnsupported {
				// this destination has no half-close capability. a joined or
				// wrapped failure must still keep its complete cause.
				err = nil
			}
		}
		results <- copyResult{leftToRight: leftToRight, bytes: count, err: err}
	}
	go copyDirection(right, left, true, onLeftToRight)
	go copyDirection(left, right, false, onRightToLeft)

	first := <-results
	var cleanupErr error
	if first.err != nil {
		cleanupErr = errors.Join(left.Close(), right.Close())
	}
	second := <-results
	if first.err == nil && second.err != nil {
		cleanupErr = errors.Join(left.Close(), right.Close())
	}
	result := Result{}
	for _, copied := range []copyResult{first, second} {
		if copied.leftToRight {
			result.LeftToRight = copied.bytes
		} else {
			result.RightToLeft = copied.bytes
		}
	}
	return result, errors.Join(first.err, second.err, cleanupErr)
}

type observedWriter struct {
	io.Writer
	observe func(int64)
}

func (w observedWriter) Write(data []byte) (int, error) {
	written, err := w.Writer.Write(data)
	if written > 0 {
		w.observe(int64(written))
	}
	return written, err
}
