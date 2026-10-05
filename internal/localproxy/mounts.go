package localproxy

import "strings"

// Mount forwards one complete path prefix to another local service.
type Mount struct {
	Prefix      string
	Target      string
	StripPrefix bool
}

// ValidMountPrefix accepts unescaped absolute paths made of whole, clean segments.
func ValidMountPrefix(prefix string) bool {
	if len(prefix) < 2 || len(prefix) > 256 || prefix[0] != '/' || prefix[len(prefix)-1] == '/' ||
		prefix == "/__tnl" || strings.HasPrefix(prefix, "/__tnl/") {
		return false
	}
	for _, segment := range strings.Split(prefix[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, character := range segment {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == '~') {
				return false
			}
		}
	}
	return true
}

func matchesMountPath(escapedPath, prefix string) bool {
	return escapedPath == prefix || strings.HasPrefix(escapedPath, prefix+"/")
}
