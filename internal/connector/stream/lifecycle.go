package stream

import "errors"

// MetadataReloadError ends a runner whose approved record is stale. callers
// must clear readiness, fetch and approve current metadata, then start a new
// runner and listener. queued connections belong only to the old runner.
type MetadataReloadError struct {
	ServiceID                          string
	ApprovedRevision, SelectedRevision int64
}

const metadataReloadMessage = "service metadata changed; refresh the approved service and restart the connector"

func (*MetadataReloadError) Error() string   { return metadataReloadMessage }
func (MetadataReloadError) String() string   { return metadataReloadMessage }
func (MetadataReloadError) GoString() string { return metadataReloadMessage }

// IsMetadataReload recognizes the caller's refresh boundary through wrappers
// and cleanup errors. errors.As also exposes the approved and selected revisions.
func IsMetadataReload(err error) bool {
	var reload *MetadataReloadError
	return errors.As(err, &reload) && reload != nil
}

func metadataReload(service string, approved, selected int64) error {
	return &MetadataReloadError{ServiceID: service, ApprovedRevision: approved, SelectedRevision: selected}
}
