//go:build js && wasm && !tnlconnector

package main

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherRejectsNativeTargetsBeforeAccess(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*service.RunConfig)
	}{
		{"no handler", func(c *service.RunConfig) { c.Handler = nil }},
		{"tcp", func(c *service.RunConfig) { c.Metadata.Protocol = controlv1.Tcp }},
		{"address", func(c *service.RunConfig) { c.Target = "127.0.0.1:8080" }},
		{"target trust", func(c *service.RunConfig) { c.Metadata.TargetTls = new(controlv1.ServiceTargetTLS) }},
		{"target discovery", func(c *service.RunConfig) { c.TargetResolver = struct{ service.TargetResolver }{} }},
		{"path mount", func(c *service.RunConfig) { c.Mounts = []proxy.Mount{{}} }},
		{"http target resolution", func(c *service.RunConfig) {
			c.ResolveHTTPTarget = func(*http.Request) (string, string, error) {
				t.Error("called native HTTP target resolver")
				return "", "", nil
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := service.RunConfig{
				Control:             struct{ service.RunControl }{},
				ServiceID:           "svc_0123456789abcdefghijkl",
				PublisherIdentityID: "pub_0123456789abcdefghijkl",
				PublisherGrantID:    "pgrant_0123456789abcdefghijkl",
				PublisherKeyID:      "pkey_0123456789abcdefghijkl",
				Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("called the handler for an unsupported target")
				}),
				Access: func(context.Context) (string, error) {
					t.Error("requested publisher access for an unsupported target")
					return "", nil
				},
			}
			cfg.Metadata.Protocol = controlv1.ServiceProtocolHTTP
			test.change(&cfg)
			if err := service.Publish(t.Context(), cfg); !errors.Is(err, service.ErrPrivateStream) {
				t.Fatalf("Publish() = %v, want ErrPrivateStream", err)
			}
		})
	}
}
