//go:build linux

package gate

import "syscall"

func setSocketMark(fd uintptr, mark uint32) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
}
