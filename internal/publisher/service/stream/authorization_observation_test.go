package stream_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
)

func TestManagedAuthorizationTimingDistinguishesDenialAndInfrastructure(t *testing.T) {
	certificates := serviceCertificates(t)
	const hostname = "web.production.storefront.example.test"
	for _, denied := range []bool{true, false} {
		t.Run(map[bool]string{true: "denied", false: "infrastructure"}[denied], func(t *testing.T) {
			metrics := observability.New("publisher")
			t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
			cause := errors.New("fixture provider cause")
			stream := servicestream.Stream{Protocol: config.ProtocolTCP, Public: true, Hostname: hostname, Target: "127.0.0.1:1", TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}},
				Visitor: servicestream.CertificateVisitor{Check: func(context.Context, *x509.Certificate) (servicestream.Decision, error) {
					if denied {
						return servicestream.Decision{}, nil
					}
					return servicestream.Decision{}, cause
				}}}
			visitor, incoming := net.Pipe()
			t.Cleanup(func() { _ = visitor.Close(); _ = incoming.Close() })
			done := make(chan error, 1)
			go func() {
				defer incoming.Close()
				done <- stream.Forward(observability.WithMetrics(t.Context(), metrics), incoming)
			}()
			secured := tls.Client(visitor, &tls.Config{RootCAs: certificates.roots, ServerName: hostname, Certificates: []tls.Certificate{certificates.client}})
			if err := secured.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			result := <-done
			if !errors.Is(result, servicestream.ErrEndpoint) || !denied && !errors.Is(result, cause) {
				t.Fatal("authorization lost its owned classification or cause", result)
			}
			outcome := "error"
			if denied {
				outcome = "denied"
			}
			families, err := metrics.Gather()
			if err != nil {
				t.Fatal(err)
			}
			var measured uint64
			for _, family := range families {
				if family.GetName() != "tnl_publisher_operation_duration_seconds" {
					continue
				}
				for _, point := range family.Metric {
					labels := map[string]string{}
					for _, label := range point.Label {
						labels[label.GetName()] = label.GetValue()
					}
					if labels["tnl_operation"] == "visitor_authorization" && labels["tnl_outcome"] == outcome && labels["tnl_exposure"] == "public" && labels["tnl_access_path"] == "public_endpoint" && labels["tnl_service_protocol"] == "tcp" {
						measured += point.GetHistogram().GetSampleCount()
					}
				}
			}
			if measured != 1 {
				t.Fatal("authorization timing misclassified policy denial or infrastructure failure", measured)
			}
		})
	}
}
