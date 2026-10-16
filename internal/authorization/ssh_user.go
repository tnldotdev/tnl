package authorization

// SSHUserValid accepts exact, portable lowercase account names, excluding root.
func SSHUserValid(user string) bool {
	if len(user) == 0 || len(user) > 32 || user == "root" {
		return false
	}
	for i := range len(user) {
		c := user[i]
		if c >= 'a' && c <= 'z' || c == '_' || i > 0 && (c >= '0' && c <= '9' || c == '-') {
			continue
		}
		return false
	}
	return true
}
