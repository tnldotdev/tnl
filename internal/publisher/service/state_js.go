//go:build js && wasm

package service

import (
	"context"
	"errors"
	"net/http"

	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
)

// LocalState can select certificates on hosts without native client state.
// feedback and demo publication are rejected before external work starts.
type LocalState = CertificateStore

type nativeHTTPControl interface{}
type nativeHTTP struct{}

var ErrFeedbackUnsupported = errors.New("service: feedback and demo publication require native client state")

func validateFeedbackPlatform(feedback, demo bool, previewID string) error {
	if feedback || demo || previewID != "" {
		return ErrFeedbackUnsupported
	}
	return nil
}

func (*HTTP) prepareNativeHTTP(context.Context) error { return nil }
func (*HTTP) startNativeHTTP() error                  { return nil }
func (HTTP) closeNativeHTTP(context.Context) error    { return nil }

func (HTTP) handleNativeReserved(http.ResponseWriter, *http.Request, *servicestream.ConnectorHTTPAuthorization) bool {
	return false
}

func (HTTP) prepareNativeApplication(_ http.ResponseWriter, r *http.Request) *http.Request {
	return r
}
