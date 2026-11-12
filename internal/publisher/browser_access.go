package publisher

import (
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func browserAccessForRun(config Config, setup controlv1.PublishRunSetup, token credentials.PublishRunToken) *httpaccess.Browser {
	controlURL, err := naming.CanonicalControlURL(config.ControlURL)
	if err != nil || setup.PublicUrl.ServiceProtocol != controlv1.Http || config.BrowserControl == nil {
		return nil
	}
	return &httpaccess.Browser{Subject: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: setup.PublicUrl.Id}, Client: config.BrowserControl,
		PreviewID: config.PreviewID, PublicURLID: setup.PublicUrl.Id, RunID: setup.PublishRun.Id,
		Number: uint64(setup.PublishRun.PublishRunNumber), Token: token, ControlURL: controlURL}
}
