package credentials

import (
	"errors"
	"net/http"
	"testing"
)

func TestBearer(t *testing.T) {
	for _, test := range []struct {
		name   string
		values []string
		want   string
	}{
		{"missing", nil, ""},
		{"opaque", []string{"Bearer AbC_123.-"}, "AbC_123.-"},
		{"mixed scheme", []string{"bEaReR token"}, "token"},
		{"repeated", []string{"Bearer token", "Bearer token"}, ""},
		{"combined", []string{"Bearer token,other"}, ""},
		{"empty", []string{"Bearer "}, ""},
		{"wrong scheme", []string{"Basic token"}, ""},
		{"extra space", []string{"Bearer  token"}, ""},
		{"trailing space", []string{"Bearer token "}, ""},
		{"tab", []string{"Bearer\ttoken"}, ""},
		{"token tab", []string{"Bearer to\tken"}, ""},
		{"line break", []string{"Bearer token\r\n"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := Bearer(http.Header{"Authorization": test.values})
			if got != test.want || (test.want == "" && !errors.Is(err, ErrInvalidAuthorization)) || (test.want != "" && err != nil) {
				t.Fatalf("Bearer = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}
