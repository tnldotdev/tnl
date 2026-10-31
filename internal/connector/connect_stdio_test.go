package connector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
)

func TestConnectStdioHalfCloseRemoteEOFAndCancellationJoin(t *testing.T) {
	for _, mode := range []string{"input-eof", "remote-eof", "cancel", "child-exit"} {
		t.Run(mode, func(t *testing.T) {
			input, producer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer producer.Close()
			consumer, output, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer consumer.Close()
			defer output.Close()
			local, err := openConnectStdio(input, output)
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			remote, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer remote.Close()
			network, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer network.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			closed := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { defer close(closed); _ = local.Close(); _ = network.Close() })
			defer func() {
				if !stop() {
					<-closed
				}
			}()
			done := make(chan error, 1)
			go func() { _, err := streamcopy.Copy(local, network); done <- err }()
			payload := []byte("SSH-2.0-client\r\n\x00\xff")
			if mode == "input-eof" {
				if _, err := producer.Write(payload); err != nil {
					t.Fatal(err)
				}
				_ = producer.Close()
				_ = remote.SetDeadline(time.Now().Add(3 * time.Second))
				got, err := io.ReadAll(remote)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal("input EOF did not half-close upstream", got, err)
				}
			}
			if mode == "input-eof" || mode == "remote-eof" {
				if _, err := remote.Write(payload); err != nil {
					t.Fatal(err)
				}
				_ = remote.(*net.TCPConn).CloseWrite()
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(consumer, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatal("stdout changed application bytes", got, err)
				}
			} else if mode == "cancel" {
				cancel()
			} else {
				_ = consumer.Close()
				_, _ = remote.Write(payload)
			}
			select {
			case err := <-done:
				switch mode {
				case "cancel":
					if !errors.Is(err, net.ErrClosed) {
						t.Fatal("canceled stdio lost its closed-socket cause", err)
					}
				case "child-exit":
					if !errors.Is(err, syscall.EPIPE) {
						t.Fatal("child exit hid its broken-pipe cause", err)
					}
				default:
					if err != nil {
						t.Fatal("clean stdio half-close failed", err)
					}
				}
			case <-time.After(3 * time.Second):
				t.Fatal("stdio did not join while the other input pipe remained open")
			}
		})
	}
}
