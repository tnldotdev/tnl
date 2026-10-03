package naming

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

type ErrorCode string

const (
	MaxLabelBytes    = 63
	MaxHostnameBytes = 253

	ErrorEmpty           ErrorCode = "empty"
	ErrorNonASCII        ErrorCode = "non_ascii"
	ErrorInvalidSyntax   ErrorCode = "invalid_syntax"
	ErrorIPLiteral       ErrorCode = "ip_literal"
	ErrorLabelTooLong    ErrorCode = "label_too_long"
	ErrorHostnameTooLong ErrorCode = "hostname_too_long"
	ErrorInvalidALabel   ErrorCode = "invalid_alabel"
	ErrorInvalidPort     ErrorCode = "invalid_port"
)

type ValidationError struct {
	Code ErrorCode
}

func (e *ValidationError) Error() string {
	return string(e.Code)
}

func CanonicalizeHostname(input string) (string, error) {
	if input == "" {
		return "", invalid(ErrorEmpty)
	}
	for i := range len(input) {
		if input[i] > 0x7f {
			return "", invalid(ErrorNonASCII)
		}
	}

	hostname := strings.ToLower(strings.TrimSuffix(input, "."))
	if hostname == "" {
		return "", invalid(ErrorEmpty)
	}
	if net.ParseIP(hostname) != nil {
		return "", invalid(ErrorIPLiteral)
	}
	if len(hostname) > MaxHostnameBytes {
		return "", invalid(ErrorHostnameTooLong)
	}

	for label := range strings.SplitSeq(hostname, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return "", invalid(ErrorInvalidSyntax)
		}
		if len(label) > MaxLabelBytes {
			return "", invalid(ErrorLabelTooLong)
		}
		for _, character := range label {
			if !isLabelCharacter(character) {
				return "", invalid(ErrorInvalidSyntax)
			}
		}
		if strings.HasPrefix(label, "xn--") && !validALabel(label) {
			return "", invalid(ErrorInvalidALabel)
		}
	}

	return hostname, nil
}

// MemberWildcardHostname returns the DNS wildcard for a one-label public URL
// beneath a member namespace. callers must validate the hostname and domain
// and check that the public URL belongs to a member.
func MemberWildcardHostname(hostname, domain string) string {
	memberHost, ok := strings.CutSuffix(hostname, "."+domain)
	if !ok {
		return ""
	}
	service, member, ok := strings.Cut(memberHost, ".")
	if !ok || service == "" || member == "" || strings.Contains(member, ".") {
		return ""
	}
	return MemberNamespaceWildcard(member+"."+domain, domain)
}

// MemberNamespaceWildcard returns a DNS wildcard beneath one member label.
func MemberNamespaceWildcard(namespace, domain string) string {
	member, ok := strings.CutSuffix(namespace, "."+domain)
	if !ok || member == "" || strings.Contains(member, ".") {
		return ""
	}
	canonical, err := CanonicalizeHostname(namespace)
	if err != nil || canonical != namespace {
		return ""
	}
	return "*." + namespace
}

func CanonicalizeAuthority(input string) (string, error) {
	if strings.HasPrefix(input, "[") || net.ParseIP(input) != nil {
		return "", invalid(ErrorIPLiteral)
	}

	hostname := input
	if strings.Contains(input, ":") {
		if strings.Count(input, ":") != 1 {
			return "", invalid(ErrorInvalidSyntax)
		}
		var port string
		hostname, port, _ = strings.Cut(input, ":")
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", invalid(ErrorInvalidPort)
		}
	}

	return CanonicalizeHostname(hostname)
}

func invalid(code ErrorCode) error {
	return &ValidationError{Code: code}
}

func isLabelCharacter(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= '0' && character <= '9' ||
		character == '-'
}

func validALabel(label string) bool {
	decoded, err := idna.Lookup.ToUnicode(label)
	if err != nil || decoded == label {
		return false
	}
	encoded, err := idna.Lookup.ToASCII(decoded)
	return err == nil && encoded == label
}

func ErrorCodeOf(err error) (ErrorCode, bool) {
	var validationError *ValidationError
	if !errors.As(err, &validationError) {
		return "", false
	}
	return validationError.Code, true
}
