package managedssh

import (
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
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
	Modes    ssh.TerminalModes
}

// Streams connects a session to its ssh channel.
type Streams struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Resize         <-chan Window
	Signals        <-chan string
	// ExitSignal receives an RFC 4254 signal name when the command is killed.
	ExitSignal func(string)
	// CloseInput ends a caller-owned input pipe after the child reports its exit.
	// blocking sources must provide it so waiting never depends on visitor EOF.
	CloseInput func()
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
	Signal   string
}

type childControl struct {
	Window *Window `json:"window,omitempty"`
	Signal string  `json:"signal,omitempty"`
}
