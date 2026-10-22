package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector"
)

func TestConnectNamesAndRemovedChoices(t *testing.T) {
	for _, name := range []string{"orders", "inventory", "profile", "setup", "shell"} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse([]string{"connect", name, "--output=json"})
		if err != nil || parsed.Command() != "connect start <name>" || flags.Connect.Start.Name != name {
			t.Fatal("service name became a command", name, err)
		}
	}
	for _, args := range [][]string{
		{"connect", "profile", "orders"}, {"connect", "setup", "orders"}, {"connect", "orders", "--local"},
		{"connect", "orders", "--client-certificate"}, {"connect", "orders", "--mtls"},
		{"connect", "stop", "--stdio"}, {"connect", "start", "--stdio"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err == nil {
			t.Fatal("obsolete choice or ambiguous command accepted", args)
		}
	}
}

func TestNativeHTTPOutputQualifiesURLAndLocalListener(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:25443", "127.0.0.1:15432", "[::1]:15432"} {
		profile := connector.Profile{Protocol: config.ProtocolHTTP, ServiceID: "svc_0123456789ABCDEFGHIJKL", Hostname: "orders.example.test", Port: 15432, URL: "https://orders.example.test:25443/"}
		var output bytes.Buffer
		if err := writeNativeConnection(&output, profile, statusOutputHuman, listen); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "curl url") || !strings.Contains(output.String(), listen) {
			t.Fatal("HTTP output did not qualify its URL and local listener", output.String())
		}
	}
}

func TestNativeProfileOutputUsesSharedRendererWidth(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, protocol := range []config.ProtocolName{config.ProtocolHTTP, config.ProtocolPostgres, config.ProtocolMySQL, config.ProtocolTCP, config.ProtocolKubernetes} {
			profile := connector.Profile{Schema: 1, ServiceID: "svc_0123456789ABCDEFGHIJKL", Protocol: protocol, Hostname: "orders.production.example.test", Public: public, Host: "127.0.0.1", Port: 15432, TLS: "service hostname verification", Command: []string{"client", "orders.production.example.test:15432"}}
			var output bytes.Buffer
			if err := writeNativeConnection(&output, profile, statusOutputHuman, "127.0.0.1:15432"); err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(output.String(), "\n") {
				if len(line) > 72 {
					t.Fatal("output exceeds shared renderer width")
				}
			}
		}
	}
}
