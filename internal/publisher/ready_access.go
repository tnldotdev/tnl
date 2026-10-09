package publisher

import (
	"slices"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// AccessInfo is a credential-free snapshot for human tunnel presentation.
// a nil team grant means no current grant snapshot is available.
type AccessInfo struct {
	AllowedIPPrefixes      []string
	BrowserSignInAvailable bool
	PublicURLScope         controlv1.PublicURLScope
	PreviewID              string
	TeamAccessEnabled      *bool
	FeedbackEnabled        bool
	FeedbackRequireSignIn  *bool
}

func readyAccessInfo(setup controlv1.PublishRunSetup, browser *browserAccess, shares *shareAccess) AccessInfo {
	info := AccessInfo{PublicURLScope: setup.PublicUrl.PublicUrlScope, BrowserSignInAvailable: browser != nil}
	if setup.PublicUrl.AllowedIpPrefixes != nil {
		info.AllowedIPPrefixes = slices.Clone(*setup.PublicUrl.AllowedIpPrefixes)
	}
	if browser != nil {
		info.PreviewID = browser.previewID
	}
	if shares != nil {
		info.TeamAccessEnabled = shares.currentTeamAccess()
	}
	return info
}
