// Package problemtype defines canonical API problem type URIs.
package problemtype

import "strings"

const origin = "https://tnl.dev/p/"

// URL returns the URI for an API problem code or private problem identifier.
func URL(code string) string { return origin + strings.ReplaceAll(code, "_", "-") }

// Is compares a problem URI to an identifier without duplicating URI spelling.
func Is(problemURI, code string) bool { return problemURI == URL(code) }
