package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"testing"
)

// a refusal is evidence only when no independent transport or cleanup failure
// is hidden beside it. HTTP status and transport errors are separate outcomes.
func previewConnectorNewWorkDenied(response *http.Response, err error) bool {
	if err != nil {
		return response == nil && previewConnectorCloseOnly(err)
	}
	return response != nil && response.StatusCode == http.StatusForbidden
}

func previewConnectorCloseOnly(err error) bool {
	if err == nil {
		return false
	}
	switch err.(type) {
	case *tls.CertificateVerificationError, x509.CertificateInvalidError,
		x509.HostnameError, x509.UnknownAuthorityError, *net.DNSError:
		// these carry independent failure even if they wrap a close sentinel.
		return false
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return false
	}
	if err == io.EOF || err == net.ErrClosed || err == syscall.ECONNREFUSED ||
		err == syscall.ECONNRESET || err == syscall.EPIPE {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !previewConnectorCloseOnly(child) {
				return false
			}
		}
		return true
	}
	if cause := errors.Unwrap(err); cause != nil {
		return previewConnectorCloseOnly(cause)
	}
	return false
}

func TestPreviewConnectorNewWorkDenialRequiresOnlyExpectedCauses(t *testing.T) {
	refused := &url.Error{Op: "Get", URL: "https://127.0.0.1:1/new-work",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}}
	other := errors.New("independent transport failure")
	invalidName := x509.HostnameError{Certificate: &x509.Certificate{}, Host: "wrong.example.test"}
	invalidCA := x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
	tlsFailure := &tls.CertificateVerificationError{Err: invalidCA}
	dnsFailure := &net.DNSError{UnwrapErr: syscall.ECONNREFUSED, Name: "wrong.example.test", IsNotFound: true}
	for _, test := range []struct {
		name     string
		response *http.Response
		err      error
		want     bool
	}{
		{"explicit forbidden", &http.Response{StatusCode: http.StatusForbidden}, nil, true},
		{"nil response and nil error", nil, nil, false},
		{"success", &http.Response{StatusCode: http.StatusOK}, nil, false},
		{"unrelated HTTP error", &http.Response{StatusCode: http.StatusInternalServerError}, nil, false},
		{"forbidden with independent error", &http.Response{StatusCode: http.StatusForbidden}, other, false},
		{"forbidden with close error", &http.Response{StatusCode: http.StatusForbidden}, io.EOF, false},
		{"connection refused", nil, refused, true},
		{"reset", nil, fmt.Errorf("read: %w", syscall.ECONNRESET), true},
		{"closed", nil, fmt.Errorf("read: %w", net.ErrClosed), true},
		{"broken pipe", nil, &os.SyscallError{Syscall: "write", Err: syscall.EPIPE}, true},
		{"EOF", nil, &url.Error{Op: "Get", Err: io.EOF}, true},
		{"all joined causes are closed", nil, fmt.Errorf("request: %w", errors.Join(refused, syscall.ECONNRESET, net.ErrClosed, io.EOF)), true},
		{"close joined with independent failure", nil, errors.Join(net.ErrClosed, other), false},
		{"wrapped join preserves independent failure", nil, &url.Error{Op: "Get", Err: fmt.Errorf("read: %w", errors.Join(io.EOF, other))}, false},
		{"canceled", nil, context.Canceled, false},
		{"canceled joined with closed", nil, errors.Join(context.Canceled, net.ErrClosed), false},
		{"deadline", nil, context.DeadlineExceeded, false},
		{"timeout", nil, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, false},
		{"timeout joined with closed", nil, errors.Join(net.ErrClosed, os.ErrDeadlineExceeded), false},
		{"invalid certificate", nil, &url.Error{Op: "Get", Err: tlsFailure}, false},
		{"invalid name", nil, &net.OpError{Op: "remote error", Net: "tcp", Err: invalidName}, false},
		{"invalid certificate joined with closed", nil, errors.Join(tlsFailure, net.ErrClosed), false},
		{"TLS verification wrapping closed", nil, &tls.CertificateVerificationError{Err: net.ErrClosed}, false},
		{"DNS wrapping refused", nil, &url.Error{Op: "Get", Err: dnsFailure}, false},
		{"DNS joined with closed", nil, errors.Join(dnsFailure, io.EOF), false},
		{"unexpected sentinel", nil, other, false},
		{"truncated message is not clean EOF", nil, io.ErrUnexpectedEOF, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := previewConnectorNewWorkDenied(test.response, test.err); got != test.want {
				t.Fatalf("new-work denial classification = %t, want %t", got, test.want)
			}
		})
	}
}
