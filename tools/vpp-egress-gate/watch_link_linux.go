//go:build linux

package gate

import (
	"io"
	"os"
	"syscall"
)

// Multicast group masks from linux/rtnetlink.h, which package syscall does not define.
const (
	rtmgrpLink       = 0x1
	rtmgrpIPv4IfAddr = 0x10
	rtmgrpIPv6IfAddr = 0x100
)

// openLinkEvents subscribes to link and address changes. Gate's own route, rule
// and sysctl updates are outside these groups, so it cannot wake itself.
func openLinkEvents() (io.ReadCloser, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: rtmgrpLink | rtmgrpIPv4IfAddr | rtmgrpIPv6IfAddr}); err != nil {
		_ = syscall.Close(fd)
		return nil, os.NewSyscallError("bind", err)
	}
	// A non-blocking descriptor uses the runtime poller, so Close interrupts a pending Read.
	return os.NewFile(uintptr(fd), "rtnetlink"), nil
}
