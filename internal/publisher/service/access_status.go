//go:build !js || !wasm

package service

import (
	"net/http"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	publisherv1 "github.com/tnldotdev/tnl/pkg/api/publisher/browser/v1"
)

type accessStatusContextKey struct{}

type accessStatusResult struct {
	status int
	value  publisherv1.BrowserAccessStatus
}

func previewAccessStatus(config HTTP, permission visitortoken.VerifiedPermission, allowed bool) accessStatusResult {
	value := publisherv1.BrowserAccessStatus{
		SchemaVersion: 1,
		Allowed:       allowed,
		PreviewId:     controlv1.PreviewID(config.PreviewID),
		ServiceId:     controlv1.ServiceID(config.Subject.ID),
		ServiceRunId:  controlv1.ServiceRunID(config.RunID),
		RunNumber:     config.Number,
	}
	status := http.StatusOK
	method := publisherv1.BrowserAccessStatusAccessMethod("")
	switch {
	case !allowed:
		status = http.StatusForbidden
		reason := publisherv1.BrowserAccessStatusReason(diagnostic.VisitorAccessDenied)
		value.Reason = &reason
	case !permission.Valid():
		method = "anonymous"
	default:
		method = "visitor"
	}
	if _, share := permission.Facts().Subject.(visitortoken.Share); allowed && share {
		method = "share"
		value.ExpiresAt = new(permission.Facts().ExpiresAt)
	}
	if method != "" {
		value.AccessMethod = &method
	}
	return accessStatusResult{status: status, value: value}
}

func writePreviewAccessStatus(response http.ResponseWriter, result accessStatusResult) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	httpjson.Write(response, result.status, result.value)
}
