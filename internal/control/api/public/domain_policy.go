package controlapi

import "errors"

var errMemberHostnameDepth = errors.New("member hostname exceeds the managed domain depth limit; use a custom domain for nested names")
