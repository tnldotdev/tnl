package publisher

import (
	"encoding/base64"
	"io"
	"net/http"
	"slices"
)

const maxCapturedBodyBytes = 32 << 10

type CapturedBody struct {
	Base64      string `json:"base64"`
	Truncated   bool   `json:"truncated"`
	Incomplete  bool   `json:"incomplete"`
	Unavailable string `json:"unavailable,omitempty"`
}

type RequestDetail struct {
	Query                    string       `json:"query"`
	QueryTruncated           bool         `json:"query_truncated"`
	RequestHeaders           http.Header  `json:"request_headers"`
	RequestHeadersTruncated  bool         `json:"request_headers_truncated"`
	ResponseHeaders          http.Header  `json:"response_headers"`
	ResponseHeadersTruncated bool         `json:"response_headers_truncated"`
	RequestBody              CapturedBody `json:"request_body"`
	ResponseBody             CapturedBody `json:"response_body"`
}

type bodyCapture struct {
	data      []byte
	truncated bool
	total     int64
}

func (b *bodyCapture) append(data []byte) {
	b.total += int64(len(data))
	remaining := maxCapturedBodyBytes - len(b.data)
	if len(data) > remaining {
		b.truncated = true
	}
	if remaining > 0 {
		b.data = append(b.data, data[:min(len(data), remaining)]...)
	}
}

func (b *bodyCapture) snapshot() CapturedBody {
	return CapturedBody{Base64: base64.StdEncoding.EncodeToString(b.data), Truncated: b.truncated}
}

type observedBodyReader struct {
	io.ReadCloser
	body *bodyCapture
}

func (b *observedBodyReader) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	if n > 0 {
		b.body.append(data[:n])
	}
	return n, err
}

func boundedRequestText(value string, limit int) (string, bool) {
	if len(value) > limit {
		return value[:limit], true
	}
	return value, false
}

func boundedRequestHeaders(headers http.Header, limit int) (http.Header, bool) {
	result := make(http.Header)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	slices.Sort(names)
	used := 0
	for _, name := range names {
		for _, value := range headers[name] {
			if used+len(name)+len(value) > limit {
				return result, true
			}
			result.Add(name, value)
			used += len(name) + len(value)
		}
	}
	return result, false
}
