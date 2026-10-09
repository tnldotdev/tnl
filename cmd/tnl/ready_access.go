package main

import (
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func readyAccessFields(info publisher.AccessInfo) []clioutput.Field {
	ip := "all IPs"
	if len(info.AllowedIPPrefixes) != 0 {
		prefixes := slices.Clone(info.AllowedIPPrefixes)
		slices.Sort(prefixes)
		ip = strings.Join(prefixes, ", ")
	}
	browser, team := "unavailable", "unavailable"
	if info.BrowserSignInAvailable {
		browser = "owning member"
		if info.PublicURLScope == controlv1.Shared {
			browser = "team admins and owners"
		}
		team = "not configured"
		if info.PreviewID != "" {
			team = "unavailable"
			if info.TeamAccessEnabled != nil {
				team = "disabled"
				if *info.TeamAccessEnabled {
					team = "current team members; preview-wide"
				}
			}
		}
	}
	return []clioutput.Field{
		{Label: "IP access", Value: ip},
		{Label: "browser sign-in", Value: browser},
		{Label: "team access", Value: team},
	}
}
