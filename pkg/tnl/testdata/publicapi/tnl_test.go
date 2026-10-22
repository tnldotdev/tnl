// package publicapi_test is a public-import-only consumer of the API at
// 52036766. compile this package explicitly; testdata is skipped by ./....
package publicapi_test

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/tnl"
)

// these are caller-owned function and interface contracts, not inferred aliases
// of the implementation. changing an argument, result, field, or method breaks
// the same source expressions that an external application uses.
var (
	_ func(context.Context, http.Handler, tnl.Options) (*tnl.Tunnel, error) = tnl.Open
	_ func(context.Context, tnl.Options) (*tnl.Publisher, error)            = tnl.PreparePublisher
	_ func(*tnl.Tunnel) string                                              = (*tnl.Tunnel).URL
	_ func(*tnl.Tunnel) error                                               = (*tnl.Tunnel).Close
	_ func(*tnl.Tunnel) error                                               = (*tnl.Tunnel).Wait
	_ io.Closer                                                             = (*tnl.Tunnel)(nil)
	_ interface {
		URL() string
		Close() error
		Wait() error
	} = (*tnl.Tunnel)(nil)

	_ error = tnl.ErrPublisherScope
	_ error = tnl.ErrPublisherSelection
	_       = tnl.Tunnel{}
	_       = tnl.Publisher{NativeControl: (tnl.Publisher{}).NativeControl}
	_       = tnl.Publisher{NativeControl: (*consumerControl)(nil)}
	_       = tnl.Options{
		EnrollmentKey: "enrollment", PublisherID: "publisher", PublisherFile: "publisher.json",
		Publisher: &tnl.Publisher{}, ServerURL: "https://control.example", StateDir: "state",
		HTTPClient: &http.Client{}, AccessMode: controlv1.Restricted, IP: []string{"127.0.0.1/32"},
		Limits:          tnl.Limits{Requests: 100, Rate: tnl.RateLimit{Requests: 5, Per: time.Second}, Concurrency: 2},
		StateProtection: tnl.ProtectionFile,
	}
)

const (
	_ tnl.StateProtection = tnl.ProtectionFile
	_ tnl.StateProtection = tnl.ProtectionKeychain
)

// an application can embed the public alias, override a public-only control
// method, and install that value in the exported NativeControl field. the
// promoted methods with unnameable parameter types must remain available too.
type consumerControl struct{ *tnl.Publisher }

func (*consumerControl) PublisherPublicURL(context.Context, string) (controlv1.PublicURL, error) {
	return controlv1.PublicURL{}, nil
}

func sameCallback[Callback any](_, _ Callback) {}

// an external consumer can infer the embedded interface and its bound method
// types even though it cannot spell the interface's defining package name.
func consumeEmbeddedControl(p *tnl.Publisher) {
	control := p.NativeControl
	var _ interface {
		PublisherPublicURL(context.Context, string) (controlv1.PublicURL, error)
		AllocatePublisherPublicURL(context.Context, string, controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, error)
		CreatePublisherRun(context.Context, string, string, string, string) (controlv1.PublishRunSetup, error)
	} = control
	sameCallback(control.ClosePublishRun, p.ClosePublishRun)
	sameCallback(control.HeartbeatPublishRun, p.HeartbeatPublishRun)
	sameCallback(control.CreateCertificateIssuance, p.CreateCertificateIssuance)
	sameCallback(control.RedeemPublishRunShare, p.RedeemPublishRunShare)
	sameCallback(control.CreateFeedbackReport, p.CreateFeedbackReport)
	_ = tnl.Publisher{NativeControl: control}
}
