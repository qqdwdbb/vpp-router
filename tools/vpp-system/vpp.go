package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	vppif "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/nat44_ei"
	"go.fd.io/govpp/binapi/vlib"
	"go.fd.io/govpp/core"
)

// thread is one of VPP's threads. Index 0 is the main thread, 1.. are the workers.
type thread struct {
	Index uint32 `json:"index"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	CPU   int    `json:"cpu"` // -1 when not pinned
}

// rxQueue is an interface's receive queue, the thread polling it and how.
type rxQueue struct {
	Index     uint32
	Interface string
	Queue     uint32
	Thread    uint32
	Mode      string // polling, interrupt, adaptive
}

// natRunning is NAT44-EI as VPP runs it now.
type natRunning struct {
	Size     natSize     `json:"size"`
	Timeouts natTimeouts `json:"timeouts"`
}

type vppAPI interface {
	Threads() ([]thread, error)
	RxQueues() ([]rxQueue, error)
	SetRxMode(index uint32, mode string) error
	SetRxPlacement(index, queue, thread uint32) error
	// NAT is nil when the NAT44-EI API is not there.
	NAT() (*natRunning, error)
	SetNATTimeouts(t natTimeouts) error
	CLI(command string) (string, error)
	Close()
}

type realVPP struct {
	conn *core.Connection
	ch   api.Channel
}

func dialVPP(socket string) (vppAPI, error) {
	conn, err := govpp.Connect(socket)
	if err != nil {
		return nil, fmt.Errorf("连接 VPP API 失败：%w", err)
	}
	ch, err := conn.NewAPIChannel()
	if err != nil {
		conn.Disconnect()
		return nil, err
	}
	ch.SetReplyTimeout(5 * time.Second)
	return &realVPP{conn: conn, ch: ch}, nil
}

func (v *realVPP) Close() {
	v.ch.Close()
	v.conn.Disconnect()
}

func checkRetval(what string, retval int32, err error) error {
	if err != nil {
		return fmt.Errorf("%s：%w", what, err)
	}
	if retval != 0 {
		return fmt.Errorf("%s：VPP 返回 %d（%s）", what, retval, api.RetvalToVPPApiError(retval))
	}
	return nil
}

func (v *realVPP) Threads() ([]thread, error) {
	reply := &vlib.ShowThreadsReply{}
	if err := checkRetval("读取线程", reply.Retval, v.ch.SendRequest(&vlib.ShowThreads{}).ReceiveReply(reply)); err != nil {
		return nil, err
	}
	var threads []thread
	for _, t := range reply.ThreadData {
		cpu := int(int32(t.CPUID))
		threads = append(threads, thread{Index: t.ID, Name: strings.TrimRight(t.Name, "\x00"), Type: strings.TrimRight(t.Type, "\x00"), CPU: cpu})
	}
	return threads, nil
}

func modeName(mode interface_types.RxMode) string {
	switch mode {
	case interface_types.RX_MODE_API_POLLING:
		return "polling"
	case interface_types.RX_MODE_API_INTERRUPT:
		return "interrupt"
	case interface_types.RX_MODE_API_ADAPTIVE:
		return "adaptive"
	}
	return "unknown"
}

func modeValue(name string) (interface_types.RxMode, bool) {
	switch name {
	case "polling":
		return interface_types.RX_MODE_API_POLLING, true
	case "interrupt":
		return interface_types.RX_MODE_API_INTERRUPT, true
	case "adaptive":
		return interface_types.RX_MODE_API_ADAPTIVE, true
	}
	return 0, false
}

func (v *realVPP) names() (map[uint32]string, error) {
	names := map[uint32]string{}
	request := v.ch.SendMultiRequest(&vppif.SwInterfaceDump{SwIfIndex: interface_types.InterfaceIndex(^uint32(0))})
	for {
		reply := &vppif.SwInterfaceDetails{}
		stop, err := request.ReceiveReply(reply)
		if err != nil {
			return nil, fmt.Errorf("读取接口：%w", err)
		}
		if stop {
			return names, nil
		}
		names[uint32(reply.SwIfIndex)] = strings.TrimRight(reply.InterfaceName, "\x00")
	}
}

func (v *realVPP) RxQueues() ([]rxQueue, error) {
	names, err := v.names()
	if err != nil {
		return nil, err
	}
	var queues []rxQueue
	request := v.ch.SendMultiRequest(&vppif.SwInterfaceRxPlacementDump{SwIfIndex: interface_types.InterfaceIndex(^uint32(0))})
	for {
		reply := &vppif.SwInterfaceRxPlacementDetails{}
		stop, err := request.ReceiveReply(reply)
		if err != nil {
			return nil, fmt.Errorf("读取收包队列：%w", err)
		}
		if stop {
			return queues, nil
		}
		index := uint32(reply.SwIfIndex)
		queues = append(queues, rxQueue{Index: index, Interface: names[index], Queue: reply.QueueID, Thread: reply.WorkerID, Mode: modeName(reply.Mode)})
	}
}

func (v *realVPP) SetRxMode(index uint32, mode string) error {
	value, ok := modeValue(mode)
	if !ok {
		return fmt.Errorf("收包方式 %q 不认识", mode)
	}
	reply := &vppif.SwInterfaceSetRxModeReply{}
	err := v.ch.SendRequest(&vppif.SwInterfaceSetRxMode{SwIfIndex: interface_types.InterfaceIndex(index), Mode: value}).ReceiveReply(reply)
	return checkRetval("设置收包方式", reply.Retval, err)
}

// SetRxPlacement moves a queue to a thread: 0 is the main thread, n is worker n-1.
func (v *realVPP) SetRxPlacement(index, queue, thread uint32) error {
	request := &vppif.SwInterfaceSetRxPlacement{SwIfIndex: interface_types.InterfaceIndex(index), QueueID: queue}
	if thread == 0 {
		request.IsMain = true
	} else {
		request.WorkerID = thread - 1
	}
	reply := &vppif.SwInterfaceSetRxPlacementReply{}
	err := v.ch.SendRequest(request).ReceiveReply(reply)
	return checkRetval("设置收包线程", reply.Retval, err)
}

func (v *realVPP) NAT() (*natRunning, error) {
	if v.ch.CheckCompatiblity(&nat44_ei.Nat44EiShowRunningConfig{}, &nat44_ei.Nat44EiShowRunningConfigReply{}) != nil {
		return nil, nil
	}
	reply := &nat44_ei.Nat44EiShowRunningConfigReply{}
	if err := checkRetval("读取 NAT44-EI 配置", reply.Retval, v.ch.SendRequest(&nat44_ei.Nat44EiShowRunningConfig{}).ReceiveReply(reply)); err != nil {
		return nil, err
	}
	t := reply.Timeouts
	return &natRunning{
		Size:     natSize{Sessions: reply.Sessions, Users: reply.Users, UserSessions: reply.UserSessions},
		Timeouts: natTimeouts{UDP: t.UDP, TCPEstablished: t.TCPEstablished, TCPTransitory: t.TCPTransitory, ICMP: t.ICMP},
	}, nil
}

func (v *realVPP) SetNATTimeouts(t natTimeouts) error {
	reply := &nat44_ei.Nat44EiSetTimeoutsReply{}
	err := v.ch.SendRequest(&nat44_ei.Nat44EiSetTimeouts{UDP: t.UDP, TCPEstablished: t.TCPEstablished, TCPTransitory: t.TCPTransitory, ICMP: t.ICMP}).ReceiveReply(reply)
	return checkRetval("设置 NAT44-EI 超时", reply.Retval, err)
}

func (v *realVPP) CLI(command string) (string, error) {
	reply := &vlib.CliInbandReply{}
	if err := checkRetval(command, reply.Retval, v.ch.SendRequest(&vlib.CliInband{Cmd: command}).ReceiveReply(reply)); err != nil {
		return "", err
	}
	return reply.Reply, nil
}

// hardware is what "show hardware-interfaces" says about a DPDK device.
type hardware struct {
	Name      string
	PCI       string // normalised, empty when not PCI
	Queues    int
	MaxQueues int
}

var (
	hwQueues = regexp.MustCompile(`^\s+rx: queues (\d+) \(max (\d+)\)`)
	hwPCI    = regexp.MustCompile(`^\s+pci: .*\baddress ([0-9a-fA-F:.]+)`)
)

func parseHardware(text string) []hardware {
	var list []hardware
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] != "Name" {
				list = append(list, hardware{Name: fields[0]})
			}
			continue
		}
		if len(list) == 0 {
			continue
		}
		hw := &list[len(list)-1]
		if m := hwQueues.FindStringSubmatch(line); m != nil {
			hw.Queues, _ = strconv.Atoi(m[1])
			hw.MaxQueues, _ = strconv.Atoi(m[2])
		} else if m := hwPCI.FindStringSubmatch(line); m != nil {
			hw.PCI, _ = pciAddress(m[1])
		}
	}
	return list
}
