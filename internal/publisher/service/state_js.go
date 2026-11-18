//go:build js && wasm

package service

import "context"

// LocalState can select certificates on hosts without native client state.
// feedback and demo publication are rejected before external work starts.
type LocalState = CertificateStore

type nativeHTTPControl interface{}

func validateFeedbackPlatform(feedback, demo bool) error {
	if feedback || demo {
		return ErrFeedbackUnsupported
	}
	return nil
}

func prepareFeedback(config HTTP) (feedbackFrontend, error) {
	return nil, validateFeedbackPlatform(config.Feedback, config.Demo)
}

func (*HTTP) prepareDemoPreview(context.Context) error { return ErrFeedbackUnsupported }
