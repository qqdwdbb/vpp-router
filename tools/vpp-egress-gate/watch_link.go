package gate

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// rtnetlink wire format. Defined here because package syscall has it only on Linux.
const (
	rtmNewLink   = 16
	rtmDelLink   = 17
	rtmNewAddr   = 20
	rtmDelAddr   = 21
	iflaIfname   = 3
	nlmsgHdrLen  = 16
	ifinfomsgLen = 16
	ifaddrmsgLen = 8
	rtaHdrLen    = 4
	nlaTypeMask  = 0x3fff
)

// Link changes come in bursts: a tunnel is created, configured and brought up in steps.
const linkEventDelay = 500 * time.Millisecond

func netlinkAlign(n int) int { return (n + 3) &^ 3 }

// netlinkInterfaceNames returns the interfaces named by rtnetlink messages. nameOf
// resolves address messages, which carry only an index. Malformed data ends parsing.
func netlinkInterfaceNames(data []byte, nameOf func(int) string) []string {
	var names []string
	for len(data) >= nlmsgHdrLen {
		length := int(binary.NativeEndian.Uint32(data))
		if length < nlmsgHdrLen || length > len(data) {
			break
		}
		body := data[nlmsgHdrLen:length]
		switch binary.NativeEndian.Uint16(data[4:]) {
		case rtmNewLink, rtmDelLink:
			if len(body) >= ifinfomsgLen {
				if name := netlinkLinkName(body[ifinfomsgLen:]); name != "" {
					names = append(names, name)
				}
			}
		case rtmNewAddr, rtmDelAddr:
			if len(body) >= ifaddrmsgLen {
				if name := nameOf(int(binary.NativeEndian.Uint32(body[4:]))); name != "" {
					names = append(names, name)
				}
			}
		}
		if next := netlinkAlign(length); next < len(data) {
			data = data[next:]
		} else {
			break
		}
	}
	return names
}

func netlinkLinkName(attrs []byte) string {
	for len(attrs) >= rtaHdrLen {
		length := int(binary.NativeEndian.Uint16(attrs))
		if length < rtaHdrLen || length > len(attrs) {
			return ""
		}
		if binary.NativeEndian.Uint16(attrs[2:])&nlaTypeMask == iflaIfname {
			name := attrs[rtaHdrLen:length]
			if end := bytes.IndexByte(name, 0); end >= 0 {
				name = name[:end]
			}
			return string(name)
		}
		next := netlinkAlign(length)
		if next >= len(attrs) {
			return ""
		}
		attrs = attrs[next:]
	}
	return ""
}

func interfaceNameByIndex(index int) string {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return ""
	}
	return iface.Name
}

// linuxExitInterfaces lists the links whose changes affect Linux exits.
func linuxExitInterfaces(cfg *Config) map[string]bool {
	names := map[string]bool{}
	for _, m := range cfg.Mappings {
		if m.Enabled && m.LinuxExit != nil {
			names[m.LinuxExit.Interface] = true
			names[m.LinuxExit.InputInterface] = true
		}
	}
	return names
}

// watchLinkEvents reads rtnetlink messages until r fails, signalling events for
// interesting interfaces. Events keeps one pending signal, so a change arriving
// during a reconciliation still causes another. Lost messages mean any interface
// may have changed. Polling remains if the watcher stops, so errors are not fatal.
func watchLinkEvents(r io.Reader, interest map[string]bool, nameOf func(int) string, delay time.Duration, events chan<- struct{}) {
	var mu sync.Mutex
	armed := false
	notify := func() {
		mu.Lock()
		defer mu.Unlock()
		if armed {
			return
		}
		armed = true
		time.AfterFunc(delay, func() {
			mu.Lock()
			armed = false
			mu.Unlock()
			select {
			case events <- struct{}{}:
			default:
			}
		})
	}
	buf := make([]byte, 65536)
	for {
		n, err := r.Read(buf)
		if err != nil {
			if errors.Is(err, syscall.ENOBUFS) {
				notify()
				continue
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("Linux exit link watcher stopped, relying on periodic checks: %s", err)
			}
			return
		}
		for _, name := range netlinkInterfaceNames(buf[:n], nameOf) {
			if interest[name] {
				notify()
				break
			}
		}
	}
}
