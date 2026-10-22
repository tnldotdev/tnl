// package oidcauth implements control-owned standard OIDC authentication.
package oidc

import "strings"

func validScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, scope := range scopes {
		if !validClaim(scope, 128) || strings.ContainsAny(scope, " \t\r\n") || seen[scope] {
			return false
		}
		seen[scope] = true
	}
	return seen["openid"]
}
