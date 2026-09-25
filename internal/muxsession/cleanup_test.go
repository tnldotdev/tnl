package muxsession

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestYamuxCleanupWithBlockedWriter(t *testing.T) {
	for _, operation := range []string{"close", "half_close", "reset"} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, peer := net.Pipe()
				defer peer.Close()
				session, err := newYamuxSession(local, true, 4096)
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				stream, err := session.OpenStream(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				// Fill the library's send queue while the peer never reads. The
				// deadline makes the final open the explicit saturation boundary.
				ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
				defer cancel()
				for {
					if _, err := session.OpenStream(ctx); err != nil {
						break
					}
				}
				started := time.Now()
				var cleanupErr error
				switch operation {
				case "close":
					cleanupErr = stream.Close()
				case "half_close":
					cleanupErr = stream.CloseWrite()
				case "reset":
					cleanupErr = stream.Reset(1)
				}
				if elapsed := time.Since(started); elapsed > 2*time.Second {
					t.Fatalf("%s waited %s for failed writer: %v", operation, elapsed, cleanupErr)
				}
				if cleanupErr == nil {
					t.Fatal("blocked cleanup lost its error")
				}
				select {
				case <-session.Done():
				default:
					t.Fatal("unusable writer retained by session")
				}
				if !errors.Is(session.Err(), errStreamCleanupBlocked) {
					t.Fatalf("lost stream-cleanup shutdown reason: %v", session.Err())
				}
			})
		})
	}
}

func TestYamuxErrRetainsPeerCloseReason(t *testing.T) {
	local, peer := net.Pipe()
	session, err := newYamuxSession(local, true, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("peer close did not stop yamux session")
	}
	if err := session.Err(); !errors.Is(err, io.EOF) {
		t.Fatalf("lost peer close reason: %v", err)
	}
}
