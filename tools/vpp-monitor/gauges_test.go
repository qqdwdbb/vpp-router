package main

import (
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"go.fd.io/govpp/adapter"
)

const testBase = 0x1000000000

// testSegment lays out a segment with the directory at offset 64, as VPP's headers define it.
func testSegment(entries ...[3]any) []byte {
	segment := make([]byte, 64+dirEntrySize*len(entries)+16)
	binary.LittleEndian.PutUint64(segment[0:], 2)
	binary.LittleEndian.PutUint64(segment[8:], testBase)
	binary.LittleEndian.PutUint64(segment[16:], 5)
	binary.LittleEndian.PutUint64(segment[32:], testBase+64)
	binary.LittleEndian.PutUint32(segment[64-vecLenOffset:], uint32(len(entries)))
	for i, e := range entries {
		entry := segment[64+i*dirEntrySize:]
		binary.LittleEndian.PutUint32(entry, uint32(e[0].(int)))
		binary.LittleEndian.PutUint64(entry[8:], e[2].(uint64))
		copy(entry[dirNameOffset:], e[1].(string))
	}
	return segment
}

func TestParseGaugesKeepsOnlyGauges(t *testing.T) {
	values, err := parseGauges(testSegment(
		[3]any{1, "/sys/heartbeat", uint64(77)},
		[3]any{statTypeGauge, "/sys/vector_rate", uint64(12)},
		[3]any{statTypeGauge, "/buffer-pools/default-numa-0/used", uint64(1207)},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values["/sys/vector_rate"] != 12 || values["/buffer-pools/default-numa-0/used"] != 1207 {
		t.Fatalf("values = %v", values)
	}
}

func TestParseGaugesRefusesWhatItCannotTrust(t *testing.T) {
	inProgress := testSegment([3]any{statTypeGauge, "/a", uint64(1)})
	binary.LittleEndian.PutUint64(inProgress[24:], 1)

	badPointer := testSegment([3]any{statTypeGauge, "/a", uint64(1)})
	binary.LittleEndian.PutUint64(badPointer[32:], testBase+uint64(len(badPointer))+4096)

	pointerBelowBase := testSegment([3]any{statTypeGauge, "/a", uint64(1)})
	binary.LittleEndian.PutUint64(pointerBelowBase[32:], testBase-64)

	hugeCount := testSegment([3]any{statTypeGauge, "/a", uint64(1)})
	binary.LittleEndian.PutUint32(hugeCount[64-vecLenOffset:], 0xffffffff)

	for name, segment := range map[string][]byte{"in progress": inProgress, "bad pointer": badPointer, "below base": pointerBelowBase, "huge count": hugeCount} {
		if _, err := parseGauges(segment); !errors.Is(err, adapter.ErrStatsDataBusy) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := parseGauges(make([]byte, 8)); err == nil {
		t.Error("a truncated segment was accepted")
	}
}

func TestMissingSocketReadsAsDisconnected(t *testing.T) {
	_, err := readGauges(t.TempDir() + "/stats.sock")
	if !errors.Is(err, adapter.ErrStatsDisconnected) {
		t.Fatalf("err = %v", err)
	}
}

func TestDescriptorArrivesWithAnEmptyMessage(t *testing.T) {
	cases := []struct {
		oobn int
		err  error
		want bool
	}{
		{24, io.EOF, true},
		{24, nil, true},
		{0, io.EOF, false},
		{0, nil, false},
		{24, errors.New("timeout"), false},
	}
	for _, tc := range cases {
		if got := descriptorArrived(tc.oobn, tc.err); got != tc.want {
			t.Errorf("%d %v: %v", tc.oobn, tc.err, got)
		}
	}
}
