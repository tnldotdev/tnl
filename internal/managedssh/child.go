package managedssh

import (
	"errors"
	"io"
)

// Window is a terminal size in character cells.
type Window struct{ Width, Height int }

// Request describes work performed only after entering the named account.
type Request struct {
	Username string
	Kind     string
	Command  string
	Term     string
	Window   Window
}

// Streams connects a session to its ssh channel.
type Streams struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Resize         <-chan Window
}

// Runner starts the installed binary's private child entry point.
type Runner struct {
	Executable   string
	Args         []string
	allowSameUID bool
}

var (
	errRootRequired  = errors.New("managed ssh requires a root service")
	errPrivilegeDrop = errors.New("ssh child privilege drop failed")
	errUnsupported   = errors.New("managed ssh is unsupported on this platform")
	errChildSetup    = errors.New("ssh child setup failed")
)

const maxSetup = 128 << 10

type childSetup struct {
	Request Request
	Address string
}

type childStatus struct {
	Ready    bool
	ExitCode int
	Failed   bool
}
