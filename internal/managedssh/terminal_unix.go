//go:build linux || darwin

package managedssh

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

var terminalCharacters = map[uint8]int{
	ssh.VINTR: unix.VINTR, ssh.VQUIT: unix.VQUIT, ssh.VERASE: unix.VERASE,
	ssh.VKILL: unix.VKILL, ssh.VEOF: unix.VEOF, ssh.VEOL: unix.VEOL,
	ssh.VEOL2: unix.VEOL2, ssh.VSTART: unix.VSTART, ssh.VSTOP: unix.VSTOP,
	ssh.VSUSP: unix.VSUSP, ssh.VREPRINT: unix.VREPRINT, ssh.VWERASE: unix.VWERASE,
	ssh.VLNEXT: unix.VLNEXT, ssh.VDISCARD: unix.VDISCARD, ssh.VFLUSH: unix.VDISCARD,
}
var inputFlags = map[uint8]termiosFlag{
	ssh.IGNPAR: unix.IGNPAR,
	ssh.PARMRK: unix.PARMRK, ssh.INPCK: unix.INPCK, ssh.ISTRIP: unix.ISTRIP,
	ssh.INLCR: unix.INLCR, ssh.IGNCR: unix.IGNCR, ssh.ICRNL: unix.ICRNL,
	ssh.IXON: unix.IXON, ssh.IXANY: unix.IXANY, ssh.IXOFF: unix.IXOFF,
	ssh.IMAXBEL: unix.IMAXBEL, ssh.IUTF8: unix.IUTF8,
}
var localFlags = map[uint8]termiosFlag{
	ssh.ISIG: unix.ISIG, ssh.ICANON: unix.ICANON, ssh.ECHO: unix.ECHO,
	ssh.ECHOE: unix.ECHOE, ssh.ECHOK: unix.ECHOK, ssh.ECHONL: unix.ECHONL,
	ssh.NOFLSH: unix.NOFLSH, ssh.TOSTOP: unix.TOSTOP, ssh.IEXTEN: unix.IEXTEN,
	ssh.ECHOCTL: unix.ECHOCTL, ssh.ECHOKE: unix.ECHOKE, ssh.PENDIN: unix.PENDIN,
}
var outputFlags = map[uint8]termiosFlag{
	ssh.OPOST: unix.OPOST, ssh.ONLCR: unix.ONLCR, ssh.OCRNL: unix.OCRNL,
	ssh.ONOCR: unix.ONOCR, ssh.ONLRET: unix.ONLRET,
}

func changeFlag(flags *termiosFlag, mask termiosFlag, value uint32) {
	if value == 0 {
		*flags &^= mask
	} else {
		*flags |= mask
	}
}

func applyTerminalModes(terminal *os.File, modes ssh.TerminalModes) error {
	t, err := unix.IoctlGetTermios(int(terminal.Fd()), getTermios)
	if err != nil {
		return err
	}
	for op, value := range modes {
		if op == ssh.VFLUSH {
			if _, explicit := modes[ssh.VDISCARD]; explicit {
				continue
			}
		}
		if index, ok := terminalCharacters[op]; ok {
			if value > 255 {
				return errChildSetup
			}
			if value == 255 {
				value = disabledCharacter
			}
			t.Cc[index] = uint8(value)
		}
		if mask, ok := inputFlags[op]; ok {
			changeFlag(&t.Iflag, mask, value)
		}
		if mask, ok := localFlags[op]; ok {
			changeFlag(&t.Lflag, mask, value)
		}
		if mask, ok := outputFlags[op]; ok {
			changeFlag(&t.Oflag, mask, value)
		}
		switch op {
		case ssh.PARENB:
			changeFlag(&t.Cflag, unix.PARENB, value)
		case ssh.PARODD:
			changeFlag(&t.Cflag, unix.PARODD, value)
		case ssh.CS7, ssh.CS8:
			if value != 0 {
				t.Cflag &^= unix.CSIZE
				if op == ssh.CS7 {
					t.Cflag |= unix.CS7
				} else {
					t.Cflag |= unix.CS8
				}
			}
		}
		if err := applyPlatformMode(t, op, value); err != nil {
			return err
		}
	}
	return unix.IoctlSetTermios(int(terminal.Fd()), setTermios, t)
}

var unixSignals = map[string]syscall.Signal{
	"ABRT": syscall.SIGABRT, "ALRM": syscall.SIGALRM, "FPE": syscall.SIGFPE,
	"HUP": syscall.SIGHUP, "ILL": syscall.SIGILL, "INT": syscall.SIGINT,
	"KILL": syscall.SIGKILL, "PIPE": syscall.SIGPIPE, "QUIT": syscall.SIGQUIT,
	"SEGV": syscall.SIGSEGV, "TERM": syscall.SIGTERM, "USR1": syscall.SIGUSR1,
	"USR2": syscall.SIGUSR2,
}

func signalName(signal syscall.Signal) string {
	for name, value := range unixSignals {
		if value == signal {
			return name
		}
	}
	switch signal {
	case syscall.SIGBUS:
		return "BUS"
	case syscall.SIGTRAP:
		return "TRAP"
	case syscall.SIGSYS:
		return "SYS"
	}
	return fmt.Sprintf("%d@tnl.dev", signal)
}
