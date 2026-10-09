package publisher

import (
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/publisherv1"
)

type accessStatusContextKey struct{}

type accessStatusResult struct {
	status int
	value  publisherv1.BrowserAccessStatus
}

func previewAccessStatus(config PublicURLServerConfig, denied, sharePermitted, teamPermitted bool, shareExpiry time.Time) accessStatusResult {
	value := publisherv1.BrowserAccessStatus{
		SchemaVersion:    1,
		Allowed:          !denied || sharePermitted || teamPermitted,
		PreviewId:        controlv1.PreviewID(config.PreviewID),
		PublicUrlId:      controlv1.PublicURLID(config.PublicURLID),
		PublishRunNumber: int64(config.PublishRunNumber),
	}
	status := http.StatusOK
	method := publisherv1.BrowserAccessStatusAccessMethod("")
	switch {
	case !denied:
		method = "ip"
	case sharePermitted:
		method = "share"
		value.ExpiresAt = &shareExpiry
	case teamPermitted:
		method = "team"
	default:
		status = http.StatusForbidden
		reason := publisherv1.BrowserAccessStatusReason(diagnostic.IPPolicyDenied)
		value.Reason = &reason
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
