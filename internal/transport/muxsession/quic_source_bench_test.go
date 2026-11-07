package muxsession

import (
	"context"
	"io"
	"testing"
	"time"
)

// compare the source fence with the ordinary listener using the same encrypted
// stream and acknowledged chunks. neither mode uses an external service.
func BenchmarkQUICSourceIsolationStream(b *testing.B) {
	for _, mode := range []string{"ordinary", "source-bound"} {
		b.Run(mode, func(b *testing.B) {
			ctx, cancel := context.WithTimeout(b.Context(), time.Minute)
			defer cancel()
			serverTLS, clientTLS := testTLSConfigs(b)
			config := QUICConfig{}
			if mode == "source-bound" {
				config.PinnedRemoteIPLimit = 8
			}
			listener, err := ListenQUIC("127.0.0.1:0", serverTLS, config)
			if err != nil {
				b.Fatal(err)
			}
			defer listener.Close()
			client, err := (QUICConnector{TLSConfig: clientTLS}).Connect(ctx, Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept(ctx)
			if err != nil {
				b.Fatal(err)
			}
			defer server.Close()
			stream, err := client.OpenStream(ctx)
			if err != nil {
				b.Fatal(err)
			}
			defer stream.Close()
			const chunkBytes = 64 << 10
			done := make(chan error, 1)
			go func() {
				incoming, err := server.AcceptStream(ctx)
				if err != nil {
					done <- err
					return
				}
				defer incoming.Close()
				buffer := make([]byte, chunkBytes)
				for {
					_, err := io.ReadFull(incoming, buffer)
					if err != nil {
						done <- err
						return
					}
					if _, err := incoming.Write([]byte{1}); err != nil {
						done <- err
						return
					}
				}
			}()
			defer func() {
				_ = stream.Close()
				cancel()
				<-done
			}()
			payload, ack := make([]byte, chunkBytes), make([]byte, 1)
			b.SetBytes(chunkBytes)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if n, err := stream.Write(payload); err != nil || n != len(payload) {
					b.Fatal("write benchmark chunk", n, err)
				}
				if _, err := io.ReadFull(stream, ack); err != nil || ack[0] != 1 {
					b.Fatal("acknowledge benchmark chunk", err)
				}
			}
			b.StopTimer()
		})
	}
}
