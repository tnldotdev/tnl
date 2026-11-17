//go:build !js || !wasm

package service

import (
	"context"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
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

func validateFeedbackPlatform(feedback, demo bool) error { return nil }

func prepareFeedback(config HTTP) (feedbackFrontend, error) {
	runtime, err := newFeedbackRuntime(config)
	if err != nil || runtime == nil {
		return nil, err
	}
	return runtime, nil
}
