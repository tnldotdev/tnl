//go:build !linux && !darwin

package managedssh

func accountShell(string) string      { return "/bin/sh" }
func dropAccount(account, bool) error { return errUnsupported }
