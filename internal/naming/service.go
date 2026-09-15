package naming

// ValidServiceName accepts 1-32 lowercase ASCII letters, digits, and hyphens,
// beginning with a letter and ending with a letter or digit. Unlike hostname
// canonicalization it does not normalize input. Callers own optionality.
func ValidServiceName(value string) bool {
	if len(value) == 0 || len(value) > 32 || value[0] < 'a' || value[0] > 'z' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
