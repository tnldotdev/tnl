package managedssh

import (
	"encoding/binary"

	"golang.org/x/crypto/ssh"
)

// terminal opcodes below 160 always carry a uint32, including unknown ones.
// opcodes at or above 160 stop decoding, as required by RFC 4254 section 8.
func parseTerminalModes(encoded string) (ssh.TerminalModes, bool) {
	modes := ssh.TerminalModes{}
	for len(encoded) > 0 {
		op := encoded[0]
		encoded = encoded[1:]
		if op == 0 {
			return modes, len(encoded) == 0 && validTerminalModes(modes)
		}
		if op >= 160 {
			return modes, validTerminalModes(modes)
		}
		if len(encoded) < 4 {
			return nil, false
		}
		value := binary.BigEndian.Uint32([]byte(encoded[:4]))
		encoded = encoded[4:]
		if op <= ssh.VDISCARD && value > 255 {
			return nil, false
		}
		modes[op] = value
	}
	return nil, false
}

func validTerminalModes(modes ssh.TerminalModes) bool {
	if len(modes) > 159 || modes[ssh.CS7] != 0 && modes[ssh.CS8] != 0 {
		return false
	}
	for op, value := range modes {
		if op == 0 || op >= 160 || op <= ssh.VDISCARD && value > 255 {
			return false
		}
	}
	return true
}

func validSignal(name string) bool {
	switch name {
	case "ABRT", "ALRM", "FPE", "HUP", "ILL", "INT", "KILL", "PIPE", "QUIT", "SEGV", "TERM", "USR1", "USR2":
		return true
	default:
		return false
	}
}
