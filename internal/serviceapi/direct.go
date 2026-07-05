package serviceapi

import (
	"net/http"
	"strconv"
)

// StatusResponse supplies status metadata for in-process generated-client
// adapters. It has no wire body; direct clients expose typed payloads only.
func StatusResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Status: strconv.Itoa(status) + " " + http.StatusText(status), Header: make(http.Header)}
}
