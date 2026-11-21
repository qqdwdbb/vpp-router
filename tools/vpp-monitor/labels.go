package main

import (
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.fd.io/govpp"
	vppif "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip"
	"go.fd.io/govpp/binapi/l2"
	"go.fd.io/govpp/binapi/tapv2"
)

// describedName matches the interfaces whose VPP name carries only an id.
var describedName = regexp.MustCompile(`^(?:tap|tun|loop)[0-9]+$`)

const (
	labelRetry = 30 * time.Second
	// VPP creates an interface before it configures it, so a new set is read again soon.
	labelSettle  = time.Minute
	labelRefresh = 5 * time.Minute
)

// InterfaceInfo is what the panel adds to VPP's name of an interface.
type InterfaceInfo struct {
	Label string
	// Placeholder marks a loopback with no address and no bridge, which only gives a NAT
	// or routing configuration something to refer to.
	Placeholder bool
}

// InterfaceLabels describes VPP's TAP, TUN and loopback interfaces, for display only.
// Series and selections keep VPP's name. The facts come from the API socket, in a short
// reading when the set of these interfaces changes or VPP restarts and every few minutes
// otherwise.
type InterfaceLabels struct {
	read func() (map[string]InterfaceInfo, error)

	mu        sync.Mutex
	labels    map[string]InterfaceInfo
	key       string
	busy      bool
	retryAt   time.Time
	nextRead  time.Time
	lastError string
	now       func() time.Time
}

func NewInterfaceLabels(read func() (map[string]InterfaceInfo, error)) *InterfaceLabels {
	return &InterfaceLabels{read: read, now: time.Now}
}

// Refresh starts a reading in the background when one is due. Key identifies the current
// set of described interfaces and is empty when there are none.
func (l *InterfaceLabels) Refresh(key string) {
	if l == nil || key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.busy || now.Before(l.retryAt) || (key == l.key && now.Before(l.nextRead)) {
		return
	}
	l.busy = true
	go func() {
		labels, err := l.read()
		l.mu.Lock()
		defer l.mu.Unlock()
		l.busy = false
		if err != nil {
			l.retryAt = l.now().Add(labelRetry)
			if err.Error() != l.lastError {
				l.lastError = err.Error()
				log.Printf("cannot read the names of the TAP interfaces: %v", err)
			}
			return
		}
		wait := labelSettle
		if key == l.key {
			wait = labelRefresh
		}
		l.labels, l.key, l.lastError, l.nextRead = labels, key, "", l.now().Add(wait)
	}()
}

// Forget makes the next Refresh read again, for a VPP that may have restarted. The old
// labels stay until then.
func (l *InterfaceLabels) Forget() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.key = ""
}

// Info returns what is known about a VPP interface.
func (l *InterfaceLabels) Info(name string) InterfaceInfo {
	if l == nil {
		return InterfaceInfo{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.labels[name]
}

// Name returns the display name of a VPP interface, its own name when it has no label.
func (l *InterfaceLabels) Name(name string) string {
	if label := l.Info(name).Label; label != "" {
		return label
	}
	return name
}

// labelKey identifies the set of described interfaces among VPP's interface names.
func labelKey(names []string) string {
	var key strings.Builder
	for _, name := range names {
		if describedName.MatchString(name) {
			key.WriteString(name)
			key.WriteByte(' ')
		}
	}
	return key.String()
}

// interfaceFacts is one reading of VPP, keyed by VPP's interface names.
type interfaceFacts struct {
	names     []string
	hosts     map[string]string // the Linux name of each TAP
	addresses map[string]string // the address to show for each loopback, if it has one
	bridged   map[string]bool
}

// describeInterfaces names each TAP after its Linux side and each loopback after its
// address. A Linux name can repeat a VPP interface or another TAP, as with a TAP named
// after the VLAN behind it, so such a label keeps VPP's name too and the rows stay distinct.
func describeInterfaces(facts interfaceFacts) map[string]InterfaceInfo {
	uses := make(map[string]int, len(facts.names)+len(facts.hosts))
	for _, name := range facts.names {
		uses[name]++
	}
	for _, host := range facts.hosts {
		uses[host]++
	}
	infos := make(map[string]InterfaceInfo, len(facts.hosts))
	for name, host := range facts.hosts {
		switch {
		case host == "" || host == name:
		case uses[host] > 1:
			infos[name] = InterfaceInfo{Label: fmt.Sprintf("%s (%s)", host, name)}
		default:
			infos[name] = InterfaceInfo{Label: host}
		}
	}
	for _, name := range facts.names {
		if !strings.HasPrefix(name, "loop") {
			continue
		}
		if address := facts.addresses[name]; address != "" {
			infos[name] = InterfaceInfo{Label: fmt.Sprintf("%s (%s)", name, address)}
		} else if !facts.bridged[name] {
			infos[name] = InterfaceInfo{Placeholder: true}
		}
	}
	return infos
}

// preferredAddress picks the address that best identifies an interface: IPv4 first, and
// never a link-local address, which every interface can have.
func preferredAddress(addresses []string) string {
	best := ""
	for _, text := range addresses {
		address, err := netip.ParseAddr(text)
		if err != nil || address.IsLinkLocalUnicast() {
			continue
		}
		if address.Is4() {
			return text
		}
		if best == "" {
			best = text
		}
	}
	return best
}

// readInterfaceLabels connects to the API socket for one reading.
func readInterfaceLabels(socket string) (map[string]InterfaceInfo, error) {
	conn, err := govpp.Connect(socket)
	if err != nil {
		return nil, fmt.Errorf("connecting to the VPP API: %w", err)
	}
	defer conn.Disconnect()
	ch, err := conn.NewAPIChannel()
	if err != nil {
		return nil, err
	}
	defer ch.Close()
	ch.SetReplyTimeout(3 * time.Second)
	if err := ch.CheckCompatiblity(&vppif.SwInterfaceDump{}, &vppif.SwInterfaceDetails{},
		&tapv2.SwInterfaceTapV2Dump{}, &tapv2.SwInterfaceTapV2Details{},
		&ip.IPAddressDump{}, &ip.IPAddressDetails{},
		&l2.BridgeDomainDump{}, &l2.BridgeDomainDetails{}); err != nil {
		return nil, err
	}
	all := interface_types.InterfaceIndex(^uint32(0))
	byIndex := make(map[uint32]string)
	vppNames := []string{}
	interfaces := ch.SendMultiRequest(&vppif.SwInterfaceDump{SwIfIndex: all})
	for {
		var reply vppif.SwInterfaceDetails
		stop, err := interfaces.ReceiveReply(&reply)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
		name := strings.TrimRight(reply.InterfaceName, "\x00")
		byIndex[uint32(reply.SwIfIndex)] = name
		vppNames = append(vppNames, name)
	}
	hosts := make(map[string]string)
	taps := ch.SendMultiRequest(&tapv2.SwInterfaceTapV2Dump{SwIfIndex: all})
	for {
		var reply tapv2.SwInterfaceTapV2Details
		stop, err := taps.ReceiveReply(&reply)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
		if name, ok := byIndex[reply.SwIfIndex]; ok {
			hosts[name] = strings.TrimRight(reply.HostIfName, "\x00")
		}
	}
	facts := interfaceFacts{names: vppNames, hosts: hosts, addresses: make(map[string]string), bridged: make(map[string]bool)}
	for index, name := range byIndex {
		if !strings.HasPrefix(name, "loop") {
			continue
		}
		var addresses []string
		for _, ipv6 := range []bool{false, true} {
			request := ch.SendMultiRequest(&ip.IPAddressDump{SwIfIndex: interface_types.InterfaceIndex(index), IsIPv6: ipv6})
			for {
				var reply ip.IPAddressDetails
				stop, err := request.ReceiveReply(&reply)
				if err != nil {
					return nil, err
				}
				if stop {
					break
				}
				addresses = append(addresses, reply.Prefix.Address.String())
			}
		}
		facts.addresses[name] = preferredAddress(addresses)
	}
	bridges := ch.SendMultiRequest(&l2.BridgeDomainDump{BdID: ^uint32(0), SwIfIndex: all})
	for {
		var reply l2.BridgeDomainDetails
		stop, err := bridges.ReceiveReply(&reply)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
		facts.bridged[byIndex[uint32(reply.BviSwIfIndex)]] = true
		for _, member := range reply.SwIfDetails {
			facts.bridged[byIndex[uint32(member.SwIfIndex)]] = true
		}
	}
	return describeInterfaces(facts), nil
}
