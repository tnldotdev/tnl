package managedssh

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type termiosFlag = uint64

const getTermios = unix.TIOCGETA
const setTermios = unix.TIOCSETA
const disabledCharacter = 255

func applyPlatformMode(t *unix.Termios, op uint8, value uint32) error {
	switch op {
	case ssh.VDSUSP:
		t.Cc[unix.VDSUSP] = uint8(value)
	case ssh.VSTATUS:
		t.Cc[unix.VSTATUS] = uint8(value)
	case ssh.TTY_OP_ISPEED:
		if supportedBaud(value) {
			t.Ispeed = uint64(value)
		}
	case ssh.TTY_OP_OSPEED:
		if supportedBaud(value) {
			t.Ospeed = uint64(value)
		}
	}
	return nil
}

func supportedBaud(value uint32) bool {
	switch value {
	case 0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400:
		return true
	default:
		return false
	}
}
