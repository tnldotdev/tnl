// Package relay copies opaque bidirectional streams while preserving half-closes.
package relay

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
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

func Copy(left, right net.Conn) (Result, error) {
	return CopyObserved(left, right, nil, nil)
}

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
		if closer, ok := destination.(interface{ CloseWrite() error }); ok {
			err = errors.Join(err, closer.CloseWrite())
		}
		results <- copyResult{leftToRight: leftToRight, bytes: count, err: normalize(err)}
	}
	go copyDirection(right, left, true, onLeftToRight)
	go copyDirection(left, right, false, onRightToLeft)

	first := <-results
	if first.err != nil {
		_ = left.Close()
		_ = right.Close()
	}
	second := <-results
	result := Result{}
	for _, copied := range []copyResult{first, second} {
		if copied.leftToRight {
			result.LeftToRight = copied.bytes
		} else {
			result.RightToLeft = copied.bytes
		}
	}
	return result, errors.Join(first.err, second.err)
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

func normalize(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, errors.ErrUnsupported) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return nil
	}
	return err
}
