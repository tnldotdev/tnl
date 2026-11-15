package serviceaccess

import (
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func Share(share controlstate.Share) controlv1.Share {
	result := controlv1.Share{
		SchemaVersion: controlv1.ReviewSchemaVersion(share.SchemaVersion),
		Id:            share.ID, TeamId: share.TeamID, GuestId: share.GuestID,
		Scope: controlv1.ShareScope(share.Scope), Label: share.Label,
		ServiceIds: share.ServiceIDs, EntryServiceId: share.EntryServiceID,
		CreatedByIdentityId: share.CreatedByIdentityID, CreatedAt: share.CreatedAt,
		ExpiresAt: share.ExpiresAt, RevokedAt: share.RevokedAt,
	}
	if share.PreviewID != "" {
		result.PreviewId = &share.PreviewID
	}
	return result
}

func SharePage(page controlstate.SharePage) controlv1.SharePage {
	result := controlv1.SharePage{
		SchemaVersion: controlstate.ReviewSchemaVersion,
		Shares:        make([]controlv1.Share, len(page.Shares)),
	}
	for index, share := range page.Shares {
		result.Shares[index] = Share(share)
	}
	if page.NextCursor != "" {
		result.NextCursor = &page.NextCursor
	}
	return result
}

func ShareCreation(share controlstate.Share, secret string) controlv1.ShareCreation {
	return controlv1.ShareCreation{
		Share: Share(share),
		Link:  "https://" + share.EntryHostname + "/__tnl/share/" + share.ID + "." + secret,
		TokenSource: controlv1.VisitorTokenShareSource{
			Kind: controlv1.VisitorTokenShare, ShareId: share.ID, Secret: secret,
		},
	}
}
