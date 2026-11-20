//go:build js && wasm && !tnlconnector

package main

import (
	"net/http"
	"syscall/js"
	"testing"
)

func TestPublisherFetchHonorsCloseWithoutForwardingHopHeaders(t *testing.T) {
	for _, value := range []string{"close", "keep-alive", "upgrade", "close, other"} {
		headers := js.Global().Get("Headers").New()
		headers.Call("set", "Connection", value)
		headers.Call("set", "Keep-Alive", "timeout=600")
		headers.Call("set", "X-App", "present")
		result := make(http.Header)
		if err := publisherResponseHeaders(result, headers); err != nil {
			t.Fatal(err)
		}
		if (result.Get("Connection") == "close") != (value == "close") ||
			result.Get("Keep-Alive") != "" || result.Get("X-App") != "present" {
			t.Fatal("Fetch response changed the connection instruction", result)
		}
	}
}
