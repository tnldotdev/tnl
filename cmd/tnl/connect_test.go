package main

import (
	"bytes"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestConnectCommandAndExactURLSelection(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"connect", "cache.example.test", "--listen", "[::1]:0"})
	if err != nil || parsed.Command() != "connect <url>" || flags.Connect.URL != "cache.example.test" || flags.Connect.Listen != "[::1]:0" {
		t.Fatalf("connect command: %v, %v", parsed, err)
	}
	for _, selector := range []string{"https://cache.example.test", "cache.example.test:6379", "-oProxyCommand=unsafe"} {
		err := runConnect(t.Context(), connectCommand{URL: selector, Listen: "127.0.0.1:0"}, &bytes.Buffer{})
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidCommand {
			t.Fatalf("invalid selector %q reached login: %v", selector, err)
		}
	}
	if err := runConnect(t.Context(), connectCommand{URL: "cache.example.test", Listen: "0.0.0.0:5432"}, &bytes.Buffer{}); err == nil {
		t.Fatalf("public listener accepted: %v", err)
	}
}

func TestConnectTargetRejectsUnsupportedProtocolsAndPorts(t *testing.T) {
	port := int32(6379)
	item := controlv1.AvailablePublicURL{Id: "url_0123456789abcdefghijkl", CanonicalHostname: "cache.example.test", ServiceProtocol: "redis", PublicPort: &port}
	if options, err := connectTarget(item); err != nil || options.Hostname != item.CanonicalHostname || options.Port != int(port) || options.PublicURLID != item.Id {
		t.Fatalf("saved Redis selection: %+v %v", options, err)
	}
	for _, mutate := range []func(*controlv1.AvailablePublicURL){
		func(item *controlv1.AvailablePublicURL) { item.ServiceProtocol = "ssh" },
		func(item *controlv1.AvailablePublicURL) { item.ServiceProtocol = "postgres" },
		func(item *controlv1.AvailablePublicURL) { item.PublicPort = nil },
		func(item *controlv1.AvailablePublicURL) { bad := int32(65536); item.PublicPort = &bad },
		func(item *controlv1.AvailablePublicURL) { item.CanonicalHostname = "cache.example.test:6379" },
	} {
		wrong := item
		mutate(&wrong)
		if _, err := connectTarget(wrong); err == nil {
			t.Fatalf("invalid TCP target accepted: %+v", wrong)
		}
	}
}
