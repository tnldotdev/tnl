//go:build !js || !wasm

package service

import (
	"context"
	"errors"
	"fmt"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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

func validateFeedbackPlatform(feedback, demo bool) error { return nil }

func (f *HTTP) prepareDemoPreview(ctx context.Context) error {
	// control creates or recovers this exact run's preview. never substitute
	// caller metadata or start browser/feedback work before validating it.
	preview, err := f.Control.CreateServiceRunPreview(ctx, f.Subject.ID, f.RunID, f.Number, f.Token)
	if err != nil {
		return fmt.Errorf("service: create demo feedback preview: %w", err)
	}
	if !opaqueid.Valid(preview.Id, opaqueid.PreviewPrefix) || preview.SchemaVersion != 1 ||
		len(preview.ServiceIds) != 1 || preview.ServiceIds[0] != f.Subject.ID {
		return failure.Wrap("create demo feedback preview", failure.ServerResponseInvalid,
			errors.New("preview has an invalid ID, schema, or service membership"))
	}
	f.PreviewID = preview.Id
	return nil
}

func prepareFeedback(config HTTP) (feedbackFrontend, error) {
	runtime, err := newFeedbackRuntime(config)
	if err != nil || runtime == nil {
		return nil, err
	}
	return runtime, nil
}
