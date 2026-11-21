package gate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Question identifies the single question supported by the gate.
type Question struct {
	Name        string
	Type, Class uint16
}

// Record is an address or alias observed in the answer section.
type Record struct {
	Owner, Value string
	TTL          uint32
}

type Message struct {
	ID, Flags uint16
	Question  Question
	Records   []Record
}

func labelsAt(packet []byte, offset int) ([]string, int, error) {
	seen := make(map[int]bool)
	var labels []string
	end, length := -1, 0
	for {
		if offset < 0 || offset >= len(packet) || seen[offset] {
			return nil, 0, errors.New("invalid DNS name")
		}
		seen[offset] = true
		size := int(packet[offset])
		if size&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return nil, 0, errors.New("short DNS pointer")
			}
			if end < 0 {
				end = offset + 2
			}
			offset = (size&0x3f)<<8 | int(packet[offset+1])
			continue
		}
		if size&0xc0 != 0 || offset+1+size > len(packet) {
			return nil, 0, errors.New("invalid DNS label")
		}
		offset++
		if size == 0 {
			if end < 0 {
				end = offset
			}
			return labels, end, nil
		}
		for _, b := range packet[offset : offset+size] {
			if b >= 128 {
				return nil, 0, errors.New("non-ASCII DNS label")
			}
		}
		length += size + 1
		if length > 254 {
			return nil, 0, errors.New("DNS name too long")
		}
		labels = append(labels, strings.ToLower(string(packet[offset:offset+size])))
		offset += size
	}
}

func nameAt(packet []byte, offset int) (string, int, error) {
	labels, end, err := labelsAt(packet, offset)
	if err != nil {
		return "", 0, err
	}
	return strings.Join(labels, "."), end, nil
}

func appendName(out []byte, labels []string, index map[string]uint16) []byte {
	for i := 0; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		if off, ok := index[suffix]; ok && off < 0x4000 {
			return append(out, byte(0xc0|off>>8), byte(off))
		}
		if len(out) < 0x4000 {
			index[suffix] = uint16(len(out))
		}
		lab := labels[i]
		if len(lab) == 0 || len(lab) > 63 {
			return append(out, 0)
		}
		out = append(out, byte(len(lab)))
		out = append(out, lab...)
	}
	return append(out, 0)
}

// Decode parses the question and routing-relevant answer records, including
// SVCB/HTTPS aliases and address hints. Malformed packets are rejected.
func Decode(packet []byte) (Message, error) {
	var m Message
	if len(packet) < 12 {
		return m, errors.New("short DNS header")
	}
	u16 := func(i int) uint16 { return binary.BigEndian.Uint16(packet[i:]) }
	m.ID, m.Flags = u16(0), u16(2)
	if u16(4) != 1 || m.Flags&0x7800 != 0 {
		return m, errors.New("only single-question DNS QUERY is supported")
	}
	name, offset, err := nameAt(packet, 12)
	if err != nil {
		return m, err
	}
	if offset+4 > len(packet) {
		return m, errors.New("short DNS question")
	}
	m.Question = Question{name, u16(offset), u16(offset + 2)}
	offset += 4
	answers, total := int(u16(6)), int(u16(6))+int(u16(8))+int(u16(10))
	for i := 0; i < total; i++ {
		owner, pos, err := nameAt(packet, offset)
		if err != nil {
			return m, err
		}
		if pos+10 > len(packet) {
			return m, errors.New("short DNS record")
		}
		kind, class := u16(pos), u16(pos+2)
		ttl, size := binary.BigEndian.Uint32(packet[pos+4:]), int(u16(pos+8))
		start, end := pos+10, pos+10+size
		if end > len(packet) {
			return m, errors.New("short DNS record data")
		}
		if i < answers && class == 1 {
			add := func(value string) { m.Records = append(m.Records, Record{owner, value, ttl}) }
			switch kind {
			case 1, 28:
				if (kind == 1 && size != 4) || (kind == 28 && size != 16) {
					return m, errors.New("bad address record")
				}
				addr, ok := netip.AddrFromSlice(packet[start:end])
				if !ok {
					return m, errors.New("bad address record")
				}
				add(addr.String())
			case 5:
				target, used, err := nameAt(packet, start)
				if err != nil {
					return m, err
				}
				if used != end {
					return m, errors.New("bad CNAME record")
				}
				add(target)
			case 64, 65:
				if size < 3 {
					return m, errors.New("short SVCB record")
				}
				target, p, err := nameAt(packet, start+2)
				if err != nil {
					return m, err
				}
				if p > end {
					return m, errors.New("short SVCB target")
				}
				if target != "" {
					add(target)
				}
				for p < end {
					if p+4 > end {
						return m, errors.New("short SVCB parameter")
					}
					key, n := u16(p), int(u16(p+2))
					p += 4
					if p+n > end {
						return m, errors.New("short SVCB parameter")
					}
					if key == 4 || key == 6 {
						width := 4
						if key == 6 {
							width = 16
						}
						if n == 0 || n%width != 0 {
							return m, errors.New("invalid SVCB address hints")
						}
						for j := p; j < p+n; j += width {
							addr, ok := netip.AddrFromSlice(packet[j : j+width])
							if !ok {
								return m, fmt.Errorf("invalid address hint")
							}
							add(addr.String())
						}
					}
					p += n
				}
			}
		}
		offset = end
	}
	return m, nil
}

// NameAt decodes a DNS name at offset, following compression pointers.
func NameAt(packet []byte, offset int) (string, int, error) {
	return nameAt(packet, offset)
}

func alpnWithoutH3(value []byte) ([]byte, error) {
	kept := make([]byte, 0, len(value))
	for pos := 0; pos < len(value); {
		size := int(value[pos])
		pos++
		if pos+size > len(value) {
			return nil, errors.New("short ALPN id")
		}
		ident := value[pos : pos+size]
		pos += size
		if string(ident) == "h3" || strings.HasPrefix(string(ident), "h3-") {
			continue
		}
		kept = append(kept, byte(size))
		kept = append(kept, ident...)
	}
	if len(kept) == 0 {
		return []byte{2, 'h', '2'}, nil
	}
	return kept, nil
}

func svcbParamsWithoutH3(params []byte) ([]byte, error) {
	if len(params) == 0 {
		return params, nil
	}
	out := make([]byte, 0, len(params))
	changed := false
	for pos := 0; pos < len(params); {
		if pos+4 > len(params) {
			return nil, errors.New("short SVCB parameter")
		}
		key := binary.BigEndian.Uint16(params[pos:])
		size := int(binary.BigEndian.Uint16(params[pos+2:]))
		pos += 4
		if pos+size > len(params) {
			return nil, errors.New("short SVCB parameter")
		}
		value := params[pos : pos+size]
		pos += size
		if key == 1 {
			filtered, err := alpnWithoutH3(value)
			if err != nil {
				return nil, err
			}
			if string(filtered) != string(value) {
				changed = true
			}
			value = filtered
		}
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[:], key)
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(value)))
		out = append(out, hdr[:]...)
		out = append(out, value...)
	}
	if changed {
		return out, nil
	}
	return params, nil
}

func takeNames(packet []byte, start, end, count int, rest bool) ([][]string, int, error) {
	pos := start
	names := make([][]string, 0, count)
	for i := 0; i < count; i++ {
		labels, next, err := labelsAt(packet, pos)
		if err != nil {
			return nil, 0, err
		}
		names = append(names, labels)
		pos = next
	}
	if pos > end {
		return nil, 0, errors.New("short name rdata")
	}
	if !rest && pos != end {
		return nil, 0, errors.New("bad name rdata")
	}
	return names, pos, nil
}

func compressedNameIn(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i]&0xc0 == 0xc0 {
			return true
		}
	}
	return false
}

func splitNamedRdata(packet []byte, kind uint16, start, end int) (prefix []byte, names [][]string, suffix, raw []byte, err error) {
	switch kind {
	case 2, 5, 7, 8, 9, 12, 39:
		names, _, err = takeNames(packet, start, end, 1, false)
		return nil, names, nil, nil, err
	case 6:
		names, pos, err := takeNames(packet, start, end, 2, true)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return nil, names, packet[pos:end], nil, nil
	case 14, 17:
		names, _, err = takeNames(packet, start, end, 2, false)
		return nil, names, nil, nil, err
	case 15, 18, 21, 36:
		if end-start < 2 {
			return nil, nil, nil, nil, errors.New("short prefixed name rdata")
		}
		names, _, err = takeNames(packet, start+2, end, 1, false)
		return packet[start : start+2], names, nil, nil, err
	case 26:
		if end-start < 2 {
			return nil, nil, nil, nil, errors.New("short PX record")
		}
		names, _, err = takeNames(packet, start+2, end, 2, false)
		return packet[start : start+2], names, nil, nil, err
	case 24, 46:
		if end-start < 18 {
			return nil, nil, nil, nil, errors.New("short SIG record")
		}
		names, pos, err := takeNames(packet, start+18, end, 1, true)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return packet[start : start+18], names, packet[pos:end], nil, nil
	case 33:
		if end-start < 6 {
			return nil, nil, nil, nil, errors.New("short SRV record")
		}
		names, _, err = takeNames(packet, start+6, end, 1, false)
		return packet[start : start+6], names, nil, nil, err
	case 35:
		prefix, names, err := splitNAPTR(packet, start, end)
		return prefix, names, nil, nil, err
	case 47:
		names, pos, err := takeNames(packet, start, end, 1, true)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return nil, names, packet[pos:end], nil, nil
	case 64, 65:
		if end-start < 3 {
			return nil, nil, nil, packet[start:end], nil
		}
		names, pos, err := takeNames(packet, start+2, end, 1, true)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return packet[start : start+2], names, packet[pos:end], nil, nil
	case 1, 16, 28, 41, 43, 44, 45, 48, 49, 50, 51, 52, 55, 61, 99, 256, 257:
		return nil, nil, nil, packet[start:end], nil
	default:
		if compressedNameIn(packet[start:end]) {
			return nil, nil, nil, nil, errors.New("compressed name in opaque RDATA")
		}
		return nil, nil, nil, packet[start:end], nil
	}
}

func splitNAPTR(packet []byte, start, end int) ([]byte, [][]string, error) {
	if end-start < 4 {
		return nil, nil, errors.New("short NAPTR record")
	}
	pos := start + 4
	for i := 0; i < 3; i++ {
		if pos >= end {
			return nil, nil, errors.New("short NAPTR record")
		}
		n := int(packet[pos])
		pos++
		if pos+n > end {
			return nil, nil, errors.New("short NAPTR record")
		}
		pos += n
	}
	names, _, err := takeNames(packet, pos, end, 1, false)
	if err != nil {
		return nil, nil, err
	}
	return packet[start:pos], names, nil
}

type parsedQ struct {
	name       []string
	typ, class uint16
}

type parsedRR struct {
	name        []string
	kind, class uint16
	ttl         uint32
	prefix      []byte
	names       [][]string
	suffix, raw []byte
}

func encodeDNS(id, flags uint16, qs []parsedQ, an, ns, ar int, rrs []parsedRR) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:], id)
	binary.BigEndian.PutUint16(out[2:], flags)
	binary.BigEndian.PutUint16(out[4:], uint16(len(qs)))
	binary.BigEndian.PutUint16(out[6:], uint16(an))
	binary.BigEndian.PutUint16(out[8:], uint16(ns))
	binary.BigEndian.PutUint16(out[10:], uint16(ar))
	index := map[string]uint16{}
	for _, q := range qs {
		out = appendName(out, q.name, index)
		var h [4]byte
		binary.BigEndian.PutUint16(h[0:], q.typ)
		binary.BigEndian.PutUint16(h[2:], q.class)
		out = append(out, h[:]...)
	}
	for _, rr := range rrs {
		out = appendName(out, rr.name, index)
		fix := len(out)
		out = append(out, make([]byte, 10)...)
		binary.BigEndian.PutUint16(out[fix:], rr.kind)
		binary.BigEndian.PutUint16(out[fix+2:], rr.class)
		binary.BigEndian.PutUint32(out[fix+4:], rr.ttl)
		rd := len(out)
		out = append(out, rr.prefix...)
		for _, n := range rr.names {
			out = appendName(out, n, index)
		}
		out = append(out, rr.suffix...)
		out = append(out, rr.raw...)
		binary.BigEndian.PutUint16(out[fix+8:], uint16(len(out)-rd))
	}
	return out
}

const dnsFlagAD uint16 = 0x0020

func rrsigCoveredType(rr parsedRR) (uint16, bool) {
	if rr.kind != 24 && rr.kind != 46 {
		return 0, false
	}
	if len(rr.prefix) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(rr.prefix), true
}

func rrsigCoversSVCB(rr parsedRR) bool {
	covered, ok := rrsigCoveredType(rr)
	return ok && (covered == 64 || covered == 65)
}

// StripHTTPSH3 removes HTTP/3 from HTTPS/SVCB ALPN so browsers use TCP
// through TPROXY. Optional addressTTL rewrites A/AAAA/CNAME TTLs in answers.
// When the packet changes, names are re-encoded so compression pointers
// stay valid after a shortened record.
//
// Gate policy is DNS split plus HTTP/2 fallback, not DNSSEC validation.
// Signed HTTPS/SVCB replies are still rewritten so h3 cannot bypass
// TPROXY. Mutation clears AD and drops covering SIG/RRSIG records so the
// packet does not claim authenticated data. Extending a Fake-IP TTL also
// clears AD. A nil result means the answer cannot be safely rewritten.
func StripHTTPSH3(packet []byte, addressTTL *uint32) []byte {
	if len(packet) < 12 {
		return packet
	}
	u16 := func(i int) uint16 { return binary.BigEndian.Uint16(packet[i:]) }
	id, flags := u16(0), u16(2)
	qd, an, ns, ar := int(u16(4)), int(u16(6)), int(u16(8)), int(u16(10))
	offset := 12
	qs := make([]parsedQ, 0, qd)
	for i := 0; i < qd; i++ {
		name, next, err := labelsAt(packet, offset)
		if err != nil || next+4 > len(packet) {
			return packet
		}
		qs = append(qs, parsedQ{name, u16(next), u16(next + 2)})
		offset = next + 4
	}
	changed := false
	httpsMutated := false
	ttlExtended := false
	unsafeRdata := false
	total := an + ns + ar
	rrs := make([]parsedRR, 0, total)
	for i := 0; i < total; i++ {
		owner, next, err := labelsAt(packet, offset)
		if err != nil || next+10 > len(packet) {
			return packet
		}
		kind, class := u16(next), u16(next+2)
		ttl := binary.BigEndian.Uint32(packet[next+4:])
		length := int(u16(next + 8))
		start, end := next+10, next+10+length
		if end > len(packet) {
			return packet
		}
		prefix, names, suffix, raw, err := splitNamedRdata(packet, kind, start, end)
		if err != nil {
			unsafeRdata = true
			raw = packet[start:end]
		}
		if (kind == 64 || kind == 65) && class == 1 {
			filtered, err := svcbParamsWithoutH3(suffix)
			if err != nil {
				return packet
			}
			if string(filtered) != string(suffix) {
				changed = true
				httpsMutated = true
				suffix = filtered
				if ttl > 60 {
					ttl = 60
				}
			}
		} else if i < an && class == 1 && (kind == 1 || kind == 5 || kind == 28) && addressTTL != nil {
			changed = changed || ttl != *addressTTL
			ttlExtended = ttlExtended || *addressTTL > ttl
			ttl = *addressTTL
		}
		rrs = append(rrs, parsedRR{owner, kind, class, ttl, prefix, names, suffix, raw})
		offset = end
	}
	if !changed {
		return packet
	}
	if unsafeRdata {
		return nil
	}
	if ttlExtended {
		flags &^= dnsFlagAD
	}
	if httpsMutated {
		flags &^= dnsFlagAD
		kept := rrs[:0]
		anKeep, nsKeep, arKeep := 0, 0, 0
		for i, rr := range rrs {
			if rrsigCoversSVCB(rr) {
				continue
			}
			kept = append(kept, rr)
			switch {
			case i < an:
				anKeep++
			case i < an+ns:
				nsKeep++
			default:
				arKeep++
			}
		}
		rrs = kept
		an, ns, ar = anKeep, nsKeep, arKeep
	}
	return encodeDNS(id, flags, qs, an, ns, ar, rrs)
}

// Servfail returns a SERVFAIL for query, copying RD/CD when the question is valid.
func Servfail(query []byte) []byte {
	return dnsReply(query, 2)
}

// NoData returns an empty NOERROR for query so a v4-only exit can hide AAAA.
func NoData(query []byte) []byte {
	return dnsReply(query, 0)
}

func dnsReply(query []byte, rcode uint16) []byte {
	base := uint16(0x8080 | rcode&0xf)
	if _, err := Decode(query); err != nil {
		id := []byte{0, 0}
		if len(query) >= 2 {
			copy(id, query[:2])
		} else if len(query) == 1 {
			id[0] = query[0]
		}
		out := make([]byte, 12)
		copy(out, id)
		binary.BigEndian.PutUint16(out[2:], base)
		return out
	}
	_, end, err := nameAt(query, 12)
	if err != nil {
		out := make([]byte, 12)
		copy(out, query[:2])
		binary.BigEndian.PutUint16(out[2:], base)
		return out
	}
	flags := binary.BigEndian.Uint16(query[2:])
	out := make([]byte, 0, end+4)
	out = append(out, query[:2]...)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:], base|(flags&0x0110))
	binary.BigEndian.PutUint16(hdr[2:], 1)
	out = append(out, hdr[:]...)
	return append(out, query[12:end+4]...)
}

// UDPSizeLimit is the client's EDNS UDP payload size, at least 512 and at most 4096.
func UDPSizeLimit(query []byte) int {
	limit := 512
	if len(query) < 12 {
		return limit
	}
	u16 := func(i int) uint16 { return binary.BigEndian.Uint16(query[i:]) }
	if u16(6) != 0 || u16(8) != 0 || u16(10) != 1 {
		return limit
	}
	_, offset, err := nameAt(query, 12)
	if err != nil || offset+4 > len(query) {
		return limit
	}
	offset += 4
	_, offset, err = nameAt(query, offset)
	if err != nil || offset+4 > len(query) {
		return limit
	}
	kind, size := u16(offset), u16(offset+2)
	if kind != 41 {
		return limit
	}
	if int(size) > limit {
		limit = int(size)
	}
	if limit > 4096 {
		limit = 4096
	}
	return limit
}

func setTruncated(answer []byte) []byte {
	if len(answer) < 4 {
		return answer
	}
	out := append([]byte{}, answer...)
	flags := binary.BigEndian.Uint16(out[2:])
	binary.BigEndian.PutUint16(out[2:], (flags&^15)|0x0200)
	return out
}
