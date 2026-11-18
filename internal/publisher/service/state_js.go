//go:build js && wasm

package service

import (
	"context"
	"errors"
	"net/http"

	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
)

// LocalState uses the host-backed certificate store instead of the native
// client database.
type LocalState = CertificateStore

// the shared frontend still owns visitor policy, sign-in, and shares. these
// empty types keep feedback state and control methods out of the wasm build.
type nativeHTTPControl interface{}
type nativeHTTP struct{}

var ErrFeedbackUnsupported = errors.New("service: feedback and demo publication require native client state")

// reject native preview settings before starting a service run or loading
// visitor policy. a preview id alone would also enable the native access status page.
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
