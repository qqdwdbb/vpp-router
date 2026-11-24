package gate

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func packet(kind uint16, data []byte) []byte {
	b := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, 'W', 'W', 'W', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1, 0xc0, 0x0c}
	h := make([]byte, 10)
	binary.BigEndian.PutUint16(h, kind)
	binary.BigEndian.PutUint16(h[2:], 1)
	binary.BigEndian.PutUint32(h[4:], 60)
	binary.BigEndian.PutUint16(h[8:], uint16(len(data)))
	return append(append(b, h...), data...)
}

func TestDecodeAddressAndCompressedAlias(t *testing.T) {
	for _, tc := range []struct {
		kind uint16
		data []byte
		want string
	}{
		{1, []byte{192, 0, 2, 1}, "192.0.2.1"},
		{5, []byte{0xc0, 0x0c}, "www.example"},
	} {
		got, err := Decode(packet(tc.kind, tc.data))
		if err != nil || got.Question.Name != "www.example" || len(got.Records) != 1 || got.Records[0].Value != tc.want || got.Records[0].TTL != 60 {
			t.Fatalf("kind %d: got %+v, %v", tc.kind, got, err)
		}
	}
}

func TestDecodeHTTPSHints(t *testing.T) {
	data := []byte{0, 1, 0, 0, 4, 0, 4, 192, 0, 2, 5}
	got, err := Decode(packet(65, data))
	if err != nil || len(got.Records) != 1 || got.Records[0].Value != "192.0.2.5" {
		t.Fatalf("got %+v, %v", got, err)
	}
	data[6] = 3
	if _, err := Decode(packet(65, data)); err == nil {
		t.Fatal("accepted invalid hint length")
	}
}

func TestDecodeRejectsMalformedPackets(t *testing.T) {
	loop := packet(1, []byte{192, 0, 2, 1})
	loop[12], loop[13] = 0xc0, 0x0c
	for _, b := range [][]byte{nil, loop, packet(1, []byte{1, 2, 3}), packet(5, []byte{0xc0})} {
		if _, err := Decode(b); err == nil {
			t.Fatalf("accepted malformed packet %x", b)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(packet(1, []byte{192, 0, 2, 1}))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b) })
}

func queryPacket() []byte {
	return dnsQueryPacket(1)
}

func aaaaQueryPacket() []byte {
	return dnsQueryPacket(28)
}

func dnsQueryPacket(qtype uint16) []byte {
	q := []byte{3, 'w', 'w', 'w', 7, 'r', 'o', 'u', 't', 'i', 'n', 'g', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0, 0, 0, 0, 1}
	binary.BigEndian.PutUint16(q[len(q)-4:], qtype)
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:], 123)
	binary.BigEndian.PutUint16(h[2:], 0x0100)
	binary.BigEndian.PutUint16(h[4:], 1)
	return append(h, q...)
}

func replyPacket(ttl uint32) []byte {
	q := queryPacket()
	binary.BigEndian.PutUint16(q[2:], 0x8180)
	binary.BigEndian.PutUint16(q[6:], 1)
	rr := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 198, 51, 100, 77}
	binary.BigEndian.PutUint32(rr[6:], ttl)
	return append(q, rr...)
}

func TestServfailCarriesNoAddresses(t *testing.T) {
	answer := Servfail(queryPacket())
	got, err := Decode(answer)
	if err != nil || got.Flags&15 != 2 || len(got.Records) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestNoDataCarriesQuestion(t *testing.T) {
	query := aaaaQueryPacket()
	answer := NoData(query)
	got, err := Decode(answer)
	if err != nil || got.Flags&15 != 0 || got.Flags&0x8000 == 0 || len(got.Records) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got.Question != (Question{"www.routing.example.net", 28, 1}) {
		t.Fatalf("question %+v", got.Question)
	}
}

func TestPointerLoopRejected(t *testing.T) {
	if _, _, err := NameAt([]byte{0xc0, 0x00}, 0); err == nil {
		t.Fatal("accepted pointer loop")
	}
}

func TestCompressedAnswer(t *testing.T) {
	got, err := Decode(replyPacket(60))
	if err != nil || len(got.Records) != 1 || got.Records[0].Value != "198.51.100.77" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestStripHTTPSLeavesARecordsAlone(t *testing.T) {
	reply := replyPacket(60)
	if string(StripHTTPSH3(reply, nil)) != string(reply) {
		t.Fatal("rewrote A record answer")
	}
}

func TestFakeIPTTLOverridePreservesOPT(t *testing.T) {
	answer := replyPacket(60)
	binary.BigEndian.PutUint16(answer[10:], 1)
	opt := []byte{0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0}
	answer = append(answer, opt...)
	ttl := uint32(30)
	changed := StripHTTPSH3(answer, &ttl)
	got, err := Decode(changed)
	if err != nil || len(got.Records) != 1 || got.Records[0].TTL != 30 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if !bytesHasSuffix(changed, opt) || len(changed) != len(answer) {
		t.Fatal("OPT not preserved")
	}
}

func bytesHasSuffix(b, suf []byte) bool {
	if len(b) < len(suf) {
		return false
	}
	return string(b[len(b)-len(suf):]) == string(suf)
}

func httpsAnswer(alpns [][]byte, extra []byte) []byte {
	return httpsAnswerFor(1, alpns, extra)
}

func httpsAnswerFor(qtype uint16, alpns [][]byte, extra []byte) []byte {
	encoded := []byte{}
	for _, item := range alpns {
		encoded = append(encoded, byte(len(item)))
		encoded = append(encoded, item...)
	}
	data := []byte{0, 1, 0}
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:], 1)
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(encoded)))
	data = append(data, hdr[:]...)
	data = append(data, encoded...)
	data = append(data, extra...)
	q := dnsQueryPacket(qtype)[12:]
	rr := []byte{0xc0, 0x0c, 0, 65, 0, 1, 0, 0, 0x0e, 0x10, 0, 0}
	binary.BigEndian.PutUint16(rr[10:], uint16(len(data)))
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:], 123)
	binary.BigEndian.PutUint16(header[2:], 0x8180)
	binary.BigEndian.PutUint16(header[4:], 1)
	binary.BigEndian.PutUint16(header[6:], 1)
	return append(append(append(header, q...), rr...), data...)
}

func httpsALPNs(pkt []byte) [][]byte {
	_, offset, err := NameAt(pkt, 12)
	if err != nil {
		return nil
	}
	offset += 4
	_, offset, err = NameAt(pkt, offset)
	if err != nil {
		return nil
	}
	length := int(binary.BigEndian.Uint16(pkt[offset+8:]))
	ttlStart := offset
	offset += 10
	_, pos, err := NameAt(pkt, offset+2)
	if err != nil {
		return nil
	}
	_ = ttlStart
	end := offset + length
	var alpns [][]byte
	for pos < end {
		key := binary.BigEndian.Uint16(pkt[pos:])
		size := int(binary.BigEndian.Uint16(pkt[pos+2:]))
		pos += 4
		value := pkt[pos : pos+size]
		pos += size
		if key != 1 {
			continue
		}
		for cursor := 0; cursor < len(value); {
			n := int(value[cursor])
			cursor++
			alpns = append(alpns, append([]byte{}, value[cursor:cursor+n]...))
			cursor += n
		}
	}
	return alpns
}

func httpsTTL(pkt []byte) uint32 {
	_, offset, _ := NameAt(pkt, 12)
	offset += 4
	_, offset, _ = NameAt(pkt, offset)
	return binary.BigEndian.Uint32(pkt[offset+4:])
}

func TestHTTPSAlpnDropsH3KeepsH2(t *testing.T) {
	answer := httpsAnswer([][]byte{[]byte("h2"), []byte("h3")}, nil)
	stripped := StripHTTPSH3(answer, nil)
	got := httpsALPNs(stripped)
	if len(got) != 1 || string(got[0]) != "h2" {
		t.Fatalf("alpns %q", got)
	}
	if string(StripHTTPSH3(stripped, nil)) != string(stripped) {
		t.Fatal("second strip changed packet")
	}
	if httpsTTL(stripped) != 60 {
		t.Fatalf("ttl %d", httpsTTL(stripped))
	}
}

func TestHTTPSAlpnH3OnlyBecomesH2(t *testing.T) {
	stripped := StripHTTPSH3(httpsAnswer([][]byte{[]byte("h3"), []byte("h3-29")}, nil), nil)
	got := httpsALPNs(stripped)
	if len(got) != 1 || string(got[0]) != "h2" {
		t.Fatalf("alpns %q", got)
	}
}

func TestHTTPSStripKeepsAddressHints(t *testing.T) {
	extra := []byte{0, 4, 0, 4, 198, 51, 100, 77}
	answer := httpsAnswer([][]byte{[]byte("h2"), []byte("h3")}, extra)
	stripped := StripHTTPSH3(answer, nil)
	got := httpsALPNs(stripped)
	if len(got) != 1 || string(got[0]) != "h2" {
		t.Fatalf("alpns %q", got)
	}
	msg, err := Decode(stripped)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range msg.Records {
		if rec.Value == "198.51.100.77" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing hint in %+v", msg.Records)
	}
}

func TestStripHTTPSH3RewritesLaterCompressionPointers(t *testing.T) {
	qname := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:], 99)
	binary.BigEndian.PutUint16(header[2:], 0x8180)
	binary.BigEndian.PutUint16(header[4:], 1)
	binary.BigEndian.PutUint16(header[6:], 3)
	question := append(append([]byte{}, qname...), 0, 65, 0, 1)

	alpn := []byte{2, 'h', '2', 2, 'h', '3'}
	rdata := []byte{0, 1, 0}
	var ph [4]byte
	binary.BigEndian.PutUint16(ph[0:], 1)
	binary.BigEndian.PutUint16(ph[2:], uint16(len(alpn)))
	rdata = append(rdata, ph[:]...)
	rdata = append(rdata, alpn...)
	https := []byte{0xc0, 0x0c, 0, 65, 0, 1, 0, 0, 0x0e, 0x10, 0, 0}
	binary.BigEndian.PutUint16(https[10:], uint16(len(rdata)))
	https = append(https, rdata...)

	cdn := []byte{3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	cdnOff := uint16(len(header) + len(question) + len(https))
	aHdr := make([]byte, 10)
	binary.BigEndian.PutUint16(aHdr[0:], 1)
	binary.BigEndian.PutUint16(aHdr[2:], 1)
	binary.BigEndian.PutUint32(aHdr[4:], 60)
	binary.BigEndian.PutUint16(aHdr[8:], 4)
	a := append(append(append([]byte{}, cdn...), aHdr...), 192, 0, 2, 9)

	aaaaHdr := make([]byte, 10)
	binary.BigEndian.PutUint16(aaaaHdr[0:], 28)
	binary.BigEndian.PutUint16(aaaaHdr[2:], 1)
	binary.BigEndian.PutUint32(aaaaHdr[4:], 60)
	binary.BigEndian.PutUint16(aaaaHdr[8:], 16)
	aaaa := []byte{byte(0xc0 | cdnOff>>8), byte(cdnOff)}
	aaaa = append(aaaa, aaaaHdr...)
	ip6 := make([]byte, 16)
	ip6[15] = 1
	aaaa = append(aaaa, ip6...)

	orig := append(append(append(append(header, question...), https...), a...), aaaa...)
	if _, err := Decode(orig); err != nil {
		t.Fatalf("original packet: %v", err)
	}
	stripped := StripHTTPSH3(orig, nil)
	if string(stripped) == string(orig) {
		t.Fatal("expected ALPN rewrite")
	}
	got, err := Decode(stripped)
	if err != nil {
		t.Fatalf("rewritten packet: %v", err)
	}
	if alpns := httpsALPNs(stripped); len(alpns) != 1 || string(alpns[0]) != "h2" {
		t.Fatalf("alpns %q", alpns)
	}
	seenA, seenAAAA := false, false
	for _, rec := range got.Records {
		if rec.Owner == "cdn.example.com" && rec.Value == "192.0.2.9" {
			seenA = true
		}
		if rec.Owner == "cdn.example.com" && rec.Value == "::1" {
			seenAAAA = true
		}
	}
	if !seenA || !seenAAAA {
		t.Fatalf("records %+v", got.Records)
	}
}

func TestStripHTTPSH3RewritesRdataCompressionPointers(t *testing.T) {
	qname := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:], 99)
	binary.BigEndian.PutUint16(header[2:], 0x8180)
	binary.BigEndian.PutUint16(header[4:], 1)
	binary.BigEndian.PutUint16(header[6:], 2)
	question := append(append([]byte{}, qname...), 0, 65, 0, 1)

	alpn := []byte{2, 'h', '2', 2, 'h', '3'}
	rdata := []byte{0, 1, 0}
	var ph [4]byte
	binary.BigEndian.PutUint16(ph[0:], 1)
	binary.BigEndian.PutUint16(ph[2:], uint16(len(alpn)))
	rdata = append(rdata, ph[:]...)
	rdata = append(rdata, alpn...)
	https := []byte{0xc0, 0x0c, 0, 65, 0, 1, 0, 0, 0x0e, 0x10, 0, 0}
	binary.BigEndian.PutUint16(https[10:], uint16(len(rdata)))
	https = append(https, rdata...)

	owner := []byte{2, 'r', 'p', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	ownerOff := uint16(len(header) + len(question) + len(https))
	rpHdr := make([]byte, 10)
	binary.BigEndian.PutUint16(rpHdr[0:], 17)
	binary.BigEndian.PutUint16(rpHdr[2:], 1)
	binary.BigEndian.PutUint32(rpHdr[4:], 60)
	rpData := []byte{byte(0xc0 | ownerOff>>8), byte(ownerOff), 0xc0, 0x0c}
	binary.BigEndian.PutUint16(rpHdr[8:], uint16(len(rpData)))
	rp := append(append(append([]byte{}, owner...), rpHdr...), rpData...)

	orig := append(append(append(header, question...), https...), rp...)
	if _, err := Decode(orig); err != nil {
		t.Fatalf("original packet: %v", err)
	}
	mbox, txt, err := rpNames(orig)
	if err != nil || mbox != "rp.example.com" || txt != "www.example.com" {
		t.Fatalf("original rp %q %q %v", mbox, txt, err)
	}
	stripped := StripHTTPSH3(orig, nil)
	if string(stripped) == string(orig) {
		t.Fatal("expected ALPN rewrite")
	}
	if _, err := Decode(stripped); err != nil {
		t.Fatalf("rewritten packet: %v", err)
	}
	mbox, txt, err = rpNames(stripped)
	if err != nil {
		t.Fatalf("rewritten rp: %v", err)
	}
	if mbox != "rp.example.com" || txt != "www.example.com" {
		t.Fatalf("rewritten rp %q %q", mbox, txt)
	}
	if alpns := httpsALPNs(stripped); len(alpns) != 1 || string(alpns[0]) != "h2" {
		t.Fatalf("alpns %q", alpns)
	}
}

func withAD(pkt []byte) []byte {
	out := append([]byte{}, pkt...)
	binary.BigEndian.PutUint16(out[2:], binary.BigEndian.Uint16(out[2:])|dnsFlagAD)
	return out
}

func appendAnswerRR(pkt []byte, kind uint16, rdata []byte) []byte {
	out := append([]byte{}, pkt...)
	an := binary.BigEndian.Uint16(out[6:])
	binary.BigEndian.PutUint16(out[6:], an+1)
	rr := []byte{0xc0, 0x0c, 0, 0, 0, 1, 0, 0, 0x0e, 0x10, 0, 0}
	binary.BigEndian.PutUint16(rr[2:], kind)
	binary.BigEndian.PutUint16(rr[10:], uint16(len(rdata)))
	return append(append(out, rr...), rdata...)
}

func rrsigRdata(covered uint16) []byte {
	prefix := make([]byte, 18)
	binary.BigEndian.PutUint16(prefix[0:], covered)
	prefix[2] = 13
	prefix[3] = 3
	binary.BigEndian.PutUint32(prefix[4:], 3600)
	binary.BigEndian.PutUint32(prefix[8:], 0x7fffffff)
	binary.BigEndian.PutUint32(prefix[12:], 1)
	binary.BigEndian.PutUint16(prefix[16:], 12345)
	signer := []byte{6, 'r', 'e', 'a', 'x', 'y', 's', 3, 'c', 'o', 'm', 0}
	return append(append(prefix, signer...), 1, 2, 3, 4, 5, 6, 7, 8)
}

func answerTypes(pkt []byte) []uint16 {
	_, offset, err := NameAt(pkt, 12)
	if err != nil {
		return nil
	}
	offset += 4
	n := int(binary.BigEndian.Uint16(pkt[6:]))
	var types []uint16
	for i := 0; i < n; i++ {
		_, next, err := NameAt(pkt, offset)
		if err != nil || next+10 > len(pkt) {
			return nil
		}
		types = append(types, binary.BigEndian.Uint16(pkt[next:]))
		length := int(binary.BigEndian.Uint16(pkt[next+8:]))
		offset = next + 10 + length
	}
	return types
}

func TestStripHTTPSH3RewritesSignedHTTPSClearsAD(t *testing.T) {
	answer := withAD(httpsAnswer([][]byte{[]byte("h2"), []byte("h3")}, nil))
	answer = appendAnswerRR(answer, 46, rrsigRdata(65))
	answer = appendAnswerRR(answer, 46, rrsigRdata(1))
	stripped := StripHTTPSH3(answer, nil)
	if stripped == nil {
		t.Fatal("signed HTTPS rewrite returned no answer")
	}
	if binary.BigEndian.Uint16(stripped[2:])&dnsFlagAD != 0 {
		t.Fatal("rewritten HTTPS reply kept AD")
	}
	if alpns := httpsALPNs(stripped); len(alpns) != 1 || string(alpns[0]) != "h2" {
		t.Fatalf("alpns %q", alpns)
	}
	got := answerTypes(stripped)
	if len(got) != 2 || got[0] != 65 || got[1] != 46 {
		t.Fatalf("records %v", got)
	}
	_, offset, err := NameAt(stripped, 12)
	if err != nil {
		t.Fatal(err)
	}
	offset += 4
	var covered []uint16
	for i := 0; i < len(got); i++ {
		_, next, err := NameAt(stripped, offset)
		if err != nil {
			t.Fatal(err)
		}
		kind := binary.BigEndian.Uint16(stripped[next:])
		length := int(binary.BigEndian.Uint16(stripped[next+8:]))
		start := next + 10
		offset = start + length
		if kind == 46 {
			covered = append(covered, binary.BigEndian.Uint16(stripped[start:]))
		}
	}
	if len(covered) != 1 || covered[0] != 1 {
		t.Fatalf("kept covering types %v", covered)
	}
}

func TestStripHTTPSH3KeepsADWhenHTTPSUnchanged(t *testing.T) {
	answer := withAD(httpsAnswer([][]byte{[]byte("h2")}, nil))
	answer = appendAnswerRR(answer, 46, rrsigRdata(65))
	stripped := StripHTTPSH3(answer, nil)
	if string(stripped) != string(answer) {
		t.Fatal("unchanged HTTPS reply was rewritten")
	}
	if binary.BigEndian.Uint16(stripped[2:])&dnsFlagAD == 0 {
		t.Fatal("cleared AD without mutating HTTPS")
	}
}

func TestStripHTTPSH3TTLShorteningKeepsAD(t *testing.T) {
	answer := withAD(replyPacket(60))
	ttl := uint32(30)
	changed := StripHTTPSH3(answer, &ttl)
	got, err := Decode(changed)
	if err != nil || len(got.Records) != 1 || got.Records[0].TTL != 30 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if binary.BigEndian.Uint16(changed[2:])&dnsFlagAD == 0 {
		t.Fatal("TTL shortening cleared AD")
	}
}

func TestStripHTTPSH3RejectsUnsafeOpaqueRdata(t *testing.T) {
	pkt := appendAnswerRR(httpsAnswer([][]byte{[]byte("h2"), []byte("h3")}, nil), 65000, []byte{0xc0, 0})
	if _, err := Decode(pkt); err != nil {
		t.Fatal(err)
	}
	if got := StripHTTPSH3(pkt, nil); got != nil {
		t.Fatal("unsafe reply must not bypass H3 filtering")
	}
}

func rpNames(pkt []byte) (string, string, error) {
	_, offset, err := NameAt(pkt, 12)
	if err != nil {
		return "", "", err
	}
	offset += 4
	answers := int(binary.BigEndian.Uint16(pkt[6:]))
	for i := 0; i < answers; i++ {
		_, next, err := NameAt(pkt, offset)
		if err != nil {
			return "", "", err
		}
		kind := binary.BigEndian.Uint16(pkt[next:])
		length := int(binary.BigEndian.Uint16(pkt[next+8:]))
		start, end := next+10, next+10+length
		offset = end
		if kind != 17 {
			continue
		}
		mbox, pos, err := NameAt(pkt, start)
		if err != nil {
			return "", "", err
		}
		txt, used, err := NameAt(pkt, pos)
		if err != nil {
			return "", "", err
		}
		if used != end {
			return "", "", fmt.Errorf("rp trailing data")
		}
		return mbox, txt, nil
	}
	return "", "", fmt.Errorf("no RP record")
}

func TestFakeIPTTLCapNeverExtendsRecords(t *testing.T) {
	for _, rr := range []struct {
		kind uint16
		data []byte
	}{
		{1, []byte{192, 0, 2, 1}},
		{28, make([]byte, 16)},
		{5, []byte{0xc0, 0x0c}},
	} {
		for _, limit := range []uint32{30, 60, 600, 604800} {
			answer := withAD(packet(rr.kind, rr.data))
			got := StripHTTPSH3(answer, &limit)
			decoded, err := Decode(got)
			want := uint32(60)
			if limit < want {
				want = limit
			}
			if err != nil || len(decoded.Records) != 1 || decoded.Records[0].TTL != want {
				t.Fatalf("type %d limit %d: %+v, %v", rr.kind, limit, decoded, err)
			}
			if limit >= 60 && string(got) != string(answer) {
				t.Fatal("unchanged TTL rewrote response")
			}
		}
	}
	zero := replyPacket(0)
	limit := uint32(300)
	if string(StripHTTPSH3(zero, &limit)) != string(zero) {
		t.Fatal("extended zero TTL")
	}
}
