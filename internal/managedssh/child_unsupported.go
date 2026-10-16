//go:build !linux && !darwin

package managedssh

import (
	"context"
	"errors"
	"net"
)

var errUnsupported = errors.New("managed ssh is unsupported on this platform")

func (*Runner) Run(context.Context, Request, Streams) (int, error)     { return 0, errUnsupported }
func (*Runner) Dial(context.Context, string, string) (net.Conn, error) { return nil, errUnsupported }
func RunChild(context.Context) error                                   { return errUnsupported }
