//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"syscall/js"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func main() {
	if err := probe(); err != nil {
		js.Global().Set("tnlWASMResult", err.Error())
		return
	}
	js.Global().Set("tnlWASMResult", "ok")
}

func probe() error {
	address, err := url.Parse(js.Global().Get("tnlWASMEndpoint").String())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	setup, stopSetup := context.WithCancel(ctx)
	transport, err := (muxsession.WebSocketConnector{}).Connect(setup, muxsession.Endpoint{
		Address: address.Host, ServerName: address.Hostname(),
	})
	stopSetup()
	if err != nil {
		return err
	}
	defer transport.Close()
	if _, ok := transport.(muxsession.AcceptedPeer); ok {
		return errors.New("host transport invented socket metadata")
	}
	if _, ok := transport.(muxsession.DatagramSession); ok {
		return errors.New("host transport advertised UDP")
	}
	session, err := tunnel.Dial(ctx, transport, tunnelv1.Message{
		Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Ingress, Credential: "portable-fixture-only",
	})
	if err != nil {
		return err
	}
	defer session.Close()
	var workers sync.WaitGroup
	results := make(chan error, 3)
	for _, payload := range [][]byte{[]byte("wasm"), bytes.Repeat([]byte("portable"), 262144)} {
		workers.Go(func() {
			stream, err := transport.OpenStream(ctx)
			if err != nil {
				results <- err
				return
			}
			defer stream.Close()
			_, err = stream.Write(payload)
			if err == nil {
				err = stream.CloseWrite()
			}
			var response []byte
			if err == nil {
				response, err = io.ReadAll(stream)
			}
			if err == nil && !bytes.Equal(response, payload) {
				err = errors.New("lost WASM stream bytes")
			}
			results <- err
		})
	}
	workers.Go(func() {
		stream, err := transport.AcceptStream(ctx)
		if err != nil {
			results <- err
			return
		}
		defer stream.Close()
		request, err := io.ReadAll(stream)
		if err == nil && string(request) != "server-open" {
			err = fmt.Errorf("unexpected reverse stream %q", request)
		}
		if err == nil {
			_, err = stream.Write(request)
		}
		if err == nil {
			err = stream.CloseWrite()
		}
		results <- err
	})
	workers.Wait()
	for range 3 {
		if err := <-results; err != nil {
			return err
		}
	}
	return nil
}
