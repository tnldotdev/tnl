package publisher

import (
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// DatabaseObservation is a completed, attributable SQL execution.
type DatabaseObservation struct {
	Protocol           controlv1.PublicURLServiceProtocol
	ReceivedAt         time.Time
	Operation          inspection.Operation
	Result             inspection.Result
	SQLState           string
	MySQLErrorCode     uint16
	Rows               int64
	ResultSets         int
	Statement          string
	StatementTruncated bool
	Duration           time.Duration
}
