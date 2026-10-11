package inspection

// Result is the outcome shared by HTTP and database inspections.
type Result string

const (
	ResultOK    Result = "ok"
	ResultError Result = "error"
)

func (r Result) Valid() bool { return r == ResultOK || r == ResultError }

// HTTPResult classifies an HTTP response without hiding its exact status.
func HTTPResult(status int) Result {
	if status >= 400 {
		return ResultError
	}
	return ResultOK
}
