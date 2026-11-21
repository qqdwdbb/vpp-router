package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/adapter/statsclient"
)

// GoVPP 0.13 and 0.14-alpha do not know VPP's gauge directory type, and return such
// entries with no data. /sys/vector_rate, /sys/input_rate, /sys/num_worker_threads and
// /buffer-pools/* are all gauges, so they are read here from a mapping of the same segment.
const (
	statTypeGauge = 9 // STAT_DIR_TYPE_GAUGE in vlib/stats/shared.h

	headerSize    = 40  // version, base, epoch, in_progress, directory_vector
	dirEntrySize  = 144 // vlib_stats_entry_t: type, union, name[128]
	dirNameOffset = 16
	vecLenOffset  = 8 // a vector's length is a u32 this far before its data
)

// gaugeClient is a StatsClient whose DumpStats fills in the entries GoVPP cannot decode.
type gaugeClient struct {
	*statsclient.StatsClient
	socket string
}

func (c *gaugeClient) DumpStats(patterns ...string) ([]adapter.StatEntry, error) {
	entries, err := c.StatsClient.DumpStats(patterns...)
	if err != nil {
		return nil, err
	}
	// The socket is dialed for each read, rather than keeping a second mapping that
	// GoVPP's reconnect would not refresh. A refusal is also the quickest sign that VPP
	// died and left its socket file behind.
	values, err := readGauges(c.socket)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].Data != nil {
			continue
		}
		if value, ok := values[string(entries[i].Name)]; ok {
			entries[i].Data = adapter.ScalarStat(value)
			entries[i].Type = adapter.ScalarIndex
		}
	}
	return entries, nil
}

func readGauges(socket string) (map[string]uint64, error) {
	segment, err := mapSegment(socket)
	if err != nil {
		return nil, err
	}
	defer syscall.Munmap(segment)
	return parseGauges(segment)
}

// mapSegment gets the segment's file descriptor from VPP and maps it read-only.
func mapSegment(socket string) ([]byte, error) {
	conn, err := net.DialTimeout("unixpacket", socket, time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", adapter.ErrStatsDisconnected, err)
	}
	defer conn.Close()
	unix := conn.(*net.UnixConn)
	unix.SetReadDeadline(time.Now().Add(time.Second))
	oob := make([]byte, syscall.CmsgSpace(4))
	buffer := make([]byte, 16)
	_, oobn, _, _, err := unix.ReadMsgUnix(buffer, oob)
	if !descriptorArrived(oobn, err) {
		return nil, fmt.Errorf("%w: %v", adapter.ErrStatsDisconnected, err)
	}
	messages, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(messages) == 0 {
		return nil, fmt.Errorf("%w: no descriptor from VPP", adapter.ErrStatsDisconnected)
	}
	fds, err := syscall.ParseUnixRights(&messages[0])
	if err != nil || len(fds) == 0 {
		return nil, fmt.Errorf("%w: no descriptor from VPP", adapter.ErrStatsDisconnected)
	}
	defer syscall.Close(fds[0])
	var stat syscall.Stat_t
	if err := syscall.Fstat(fds[0], &stat); err != nil {
		return nil, err
	}
	return syscall.Mmap(fds[0], 0, int(stat.Size), syscall.PROT_READ, syscall.MAP_SHARED)
}

// descriptorArrived says whether a read delivered the descriptor. VPP sends it with no
// payload, which Go reports as EOF on a sequenced socket along with the control data.
func descriptorArrived(oobn int, err error) bool {
	return oobn > 0 && (err == nil || errors.Is(err, io.EOF))
}

// parseGauges returns every gauge in a mapped segment. Every offset comes from memory VPP
// is changing, so each is checked, and a directory that moved during the walk is discarded.
func parseGauges(segment []byte) (map[string]uint64, error) {
	if len(segment) < headerSize {
		return nil, fmt.Errorf("stats segment of %d bytes", len(segment))
	}
	u64 := func(offset uint64) uint64 { return binary.LittleEndian.Uint64(segment[offset:]) }
	epoch := u64(16)
	if u64(24) != 0 {
		return nil, adapter.ErrStatsDataBusy
	}
	size := uint64(len(segment))
	// A pointer is relative to the address VPP mapped the segment at.
	offset := u64(32) - u64(8)
	if offset < vecLenOffset || offset >= size {
		return nil, adapter.ErrStatsDataBusy
	}
	count := uint64(binary.LittleEndian.Uint32(segment[offset-vecLenOffset:]))
	if count > (size-offset)/dirEntrySize {
		return nil, adapter.ErrStatsDataBusy
	}
	values := make(map[string]uint64)
	for i := uint64(0); i < count; i++ {
		entry := segment[offset+i*dirEntrySize : offset+(i+1)*dirEntrySize]
		if binary.LittleEndian.Uint32(entry) != statTypeGauge {
			continue
		}
		name := entry[dirNameOffset:]
		for n, b := range name {
			if b == 0 {
				name = name[:n]
				break
			}
		}
		values[string(name)] = binary.LittleEndian.Uint64(entry[8:])
	}
	if u64(16) != epoch || u64(24) != 0 {
		return nil, adapter.ErrStatsDataBusy
	}
	return values, nil
}
