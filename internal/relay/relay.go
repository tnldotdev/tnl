// Package relay copies opaque bidirectional streams while preserving half-closes.
package relay

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

func Copy(left, right net.Conn) (Result, error) {
	type copyResult struct {
		leftToRight bool
		bytes       int64
		err         error
	}
	results := make(chan copyResult, 2)
	copyDirection := func(destination, source net.Conn, leftToRight bool) {
		buffer := buffers.Get().(*[]byte)
		count, err := io.CopyBuffer(destination, source, *buffer)
		buffers.Put(buffer)
		if closer, ok := destination.(interface{ CloseWrite() error }); ok {
			err = errors.Join(err, closer.CloseWrite())
		}
		results <- copyResult{leftToRight: leftToRight, bytes: count, err: normalize(err)}
	}
	go copyDirection(right, left, true)
	go copyDirection(left, right, false)

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

func normalize(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, errors.ErrUnsupported) {
		return nil
	}
	return err
}
