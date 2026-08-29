package tailbench

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

func OpenEchoStream(ctx context.Context, open func(context.Context) (net.Conn, error)) (net.Conn, time.Duration, error) {
	started := time.Now()
	conn, err := open(ctx)
	if err != nil {
		return nil, 0, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		conn.Close()
		return nil, 0, err
	}
	var response [1]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		conn.Close()
		return nil, 0, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, time.Since(started), nil
}

func RoundTripBytes(conn net.Conn, total int) error {
	buffer := make([]byte, min(total, 16*1024))
	for remaining := total; remaining > 0; {
		chunk := min(remaining, len(buffer))
		if _, err := conn.Write(buffer[:chunk]); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, buffer[:chunk]); err != nil {
			return err
		}
		remaining -= chunk
	}
	return nil
}

func CloseEchoStream(ctx context.Context, conn net.Conn) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	closeWriter, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("stream does not support CloseWrite")
	}
	writeErr := closeWriter.CloseWrite()
	_, readErr := io.Copy(io.Discard, conn)
	return errors.Join(writeErr, readErr, conn.Close())
}
