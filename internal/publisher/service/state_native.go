//go:build !js || !wasm

package service

import (
	"context"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// LocalState is the native persistence consumed by service publication. the
// caller owns its database; the run owns feedback workers and demo cleanup.
// portable publishers select CertificateStore instead of native client state.
type LocalState interface {
	CertificateStore
	feedbackState
}

type feedbackState interface {
	Feedback(context.Context, string, string, clientstate.FeedbackAuthorize) (*clientstate.FeedbackStore, error)
	DemoFeedback(context.Context, string, clientstate.FeedbackAuthorize) (*clientstate.FeedbackStore, error)
	DiscardDemoFeedback(context.Context, string) error
}

type nativeHTTPControl interface {
	FeedbackClient
	CreateServiceRunPreview(context.Context, string, string, int64, credentials.ServiceRunToken) (controlv1.Preview, error)
}

func validateFeedbackPlatform(bool, bool, string) error { return nil }
