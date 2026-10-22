package inspection

import (
	"errors"
	"time"
)

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
	Mode      Mode
	Retention time.Duration
	MaxBytes  int64
}

func (p Policy) Validate() error {
	if !p.Mode.Valid() {
		return errors.New("inspection mode must be none or summary")
	}
	if p.Retention != 0 && (p.Retention < time.Minute || p.Retention > MaxRetention) {
		return errors.New("inspection retention must be between one minute and thirty days")
	}
	if p.MaxBytes != 0 && (p.MaxBytes < MinMaxBytes || p.MaxBytes > MaxMaxBytes) {
		return errors.New("inspection byte budget must be between 1 MiB and 1 GiB")
	}
	return nil
}

type Mode string

const (
	None        Mode = "none"
	SummaryMode Mode = "summary"
)

func (m Mode) Valid() bool { return m == "" || m == None || m == SummaryMode }

// Summary is the only publisher observation contract. it cannot carry SQL,
// arguments, headers, credentials, or reply bodies. callbacks must return quickly.
type Summary struct {
	Protocol       Protocol
	ReceivedAt     time.Time
	Duration       time.Duration
	Result         Result
	Operation      Operation
	Command        string
	SQLState       string
	MySQLErrorCode uint16
	Rows           int64
	ResultSets     int
	Method         string
	Path           string
	Status         int
	Origin         string
}

type Observer func(Summary)

const MaxCount = 1_000_000_000

func SQLStateOrEmpty(value string) string {
	if ValidSQLState(value) {
		return value
	}
	return ""
}

// HTTPResult classifies an HTTP response without hiding its exact status.
func HTTPResult(status int) Result {
	if status >= 400 {
		return ResultError
	}
	return ResultOK
}
