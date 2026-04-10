package naming

import (
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
	validationError, ok := err.(*ValidationError)
	if !ok {
		return "", false
	}
	return validationError.Code, true
}
