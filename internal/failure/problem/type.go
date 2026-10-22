// Package problemtype defines canonical API problem type URIs.
package problemtype

import "strings"

const origin = "https://tnl.dev/p/"

// URL returns the URI for an API problem code or private problem identifier.
func URL(code string) string { return origin + strings.ReplaceAll(code, "_", "-") }

// HelpURL adds only known, non-sensitive context; the problem type stays canonical.
func HelpURL(code, caseID string) string {
	result := URL(code)
	switch {
	case code == "unauthenticated" && caseID == "cluster-secret",
		code == "invalid_json" && caseID == "trailing-content":
		return result + "?case=" + caseID
	}
	return result
}

// Is compares a problem URI to an identifier without duplicating URI spelling.
func Is(problemURI, code string) bool { return problemURI == URL(code) }
