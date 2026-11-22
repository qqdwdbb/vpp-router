package main

import (
	"net"
	"syscall"
)

// bindControl binds a test's socket to a Linux device, so it leaves through that device.
func bindControl(device string) func(network, address string, c syscall.RawConn) error {
	if device == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var err error
		if controlErr := c.Control(func(fd uintptr) {
			err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
		}); controlErr != nil {
			return controlErr
		}
		return err
	}
}

// peerPID is the process on the other end of a Unix socket.
func peerPID(conn *net.UnixConn) int {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0
	}
	pid := 0
	raw.Control(func(fd uintptr) {
		if cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
			pid = int(cred.Pid)
		}
	})
	return pid
}
