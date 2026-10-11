package inspection

import "time"

const (
	DefaultRetention = 24 * time.Hour
	MaxRetention     = 30 * 24 * time.Hour
	DefaultMaxBytes  = 64 << 20
	MinMaxBytes      = 1 << 20
	MaxMaxBytes      = 1 << 30
)

// Result is the outcome shared by HTTP and supported TCP inspections.
type Result string

const (
	ResultOK    Result = "ok"
	ResultError Result = "error"
)

func (r Result) Valid() bool { return r == ResultOK || r == ResultError }

type Operation string

const (
	OperationQuery   Operation = "query"
	OperationExecute Operation = "execute"
)

func (o Operation) Valid() bool { return o == OperationQuery || o == OperationExecute }

func ValidSQLState(value string) bool {
	if len(value) != 5 {
		return false
	}
	for _, code := range value {
		if code < 'A' || code > 'Z' {
			if code < '0' || code > '9' {
				return false
			}
		}
	}
	return true
}

type Policy struct {
	Retention time.Duration
	MaxBytes  int64
}

// HTTPResult classifies an HTTP response without hiding its exact status.
func HTTPResult(status int) Result {
	if status >= 400 {
		return ResultError
	}
	return ResultOK
}
