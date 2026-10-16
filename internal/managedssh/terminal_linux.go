package managedssh

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type termiosFlag = uint32

const getTermios = unix.TCGETS
const setTermios = unix.TCSETS
const disabledCharacter = 0

var baudCodes = map[uint32]uint32{
	0: unix.B0, 50: unix.B50, 75: unix.B75, 110: unix.B110, 134: unix.B134,
	150: unix.B150, 200: unix.B200, 300: unix.B300, 600: unix.B600,
	1200: unix.B1200, 1800: unix.B1800, 2400: unix.B2400, 4800: unix.B4800,
	9600: unix.B9600, 19200: unix.B19200, 38400: unix.B38400,
	57600: unix.B57600, 115200: unix.B115200, 230400: unix.B230400,
}

func applyPlatformMode(t *unix.Termios, op uint8, value uint32) error {
	switch op {
	case ssh.VSWTCH:
		if value == 255 {
			value = disabledCharacter
		}
		t.Cc[unix.VSWTC] = uint8(value)
	case ssh.IUCLC:
		changeFlag(&t.Iflag, unix.IUCLC, value)
	case ssh.OLCUC:
		changeFlag(&t.Oflag, unix.OLCUC, value)
	case ssh.XCASE:
		changeFlag(&t.Lflag, unix.XCASE, value)
	case ssh.TTY_OP_ISPEED, ssh.TTY_OP_OSPEED:
		if code, ok := baudCodes[value]; ok {
			if op == ssh.TTY_OP_ISPEED {
				t.Ispeed = value
				t.Cflag = t.Cflag&^unix.CIBAUD | code<<16
			} else {
				t.Ospeed = value
				t.Cflag = t.Cflag&^unix.CBAUD | code
			}
		}
	}
	return nil
}
