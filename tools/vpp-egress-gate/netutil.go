package gate

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

func parseAddr(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("a unicast address without a scope suffix is required")
	}
	return addr, nil
}

func parsePrefixStrict(value string) (netip.Prefix, error) {
	if !strings.Contains(value, "/") {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if prefix.Addr() != prefix.Masked().Addr() {
		return netip.Prefix{}, fmt.Errorf("host bits set in prefix %s", value)
	}
	return prefix, nil
}

func hostPrefix(addr netip.Addr) netip.Prefix {
	return netip.PrefixFrom(addr, addr.BitLen())
}

func prefixString(p netip.Prefix) string {
	return p.Masked().String()
}

func isIP(value string) bool {
	_, err := netip.ParseAddr(value)
	return err == nil
}

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Addr().BitLen() == b.Addr().BitLen() && a.Overlaps(b)
}

func prefixSubnetOf(a, b netip.Prefix) bool {
	return a.Addr().BitLen() == b.Addr().BitLen() && b.Contains(a.Addr()) && a.Bits() >= b.Bits()
}

func xorBit(addr netip.Addr, bitFromMSB int) netip.Addr {
	if addr.Is4() {
		a4 := addr.As4()
		v := binary.BigEndian.Uint32(a4[:])
		v ^= 1 << (31 - bitFromMSB)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		out, _ := netip.AddrFromSlice(b[:])
		return out
	}
	raw := addr.As16()
	byteIndex := bitFromMSB / 8
	bit := 7 - (bitFromMSB % 8)
	raw[byteIndex] ^= 1 << bit
	out, _ := netip.AddrFromSlice(raw[:])
	return out
}

func siblingOf(p netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(xorBit(p.Addr(), p.Bits()-1), p.Bits()).Masked()
}

func excludePrefix(whole, sub netip.Prefix) []netip.Prefix {
	if whole.Bits() == sub.Bits() {
		return nil
	}
	var out []netip.Prefix
	current := whole.Masked()
	for current.Bits() < sub.Bits() {
		n := current.Bits() + 1
		left := netip.PrefixFrom(current.Addr(), n).Masked()
		right := siblingOf(left)
		if left.Contains(sub.Addr()) {
			out = append(out, right)
			current = left
		} else {
			out = append(out, left)
			current = right
		}
	}
	return out
}

func subtractPrefix(parts []netip.Prefix, covered netip.Prefix) []netip.Prefix {
	var result []netip.Prefix
	for _, part := range parts {
		if !prefixesOverlap(part, covered) {
			result = append(result, part)
		} else if prefixSubnetOf(part, covered) {
			continue
		} else {
			result = append(result, excludePrefix(part, covered)...)
		}
	}
	return result
}

func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	if p.Addr().Is4() {
		a4 := p.Addr().As4()
		v := binary.BigEndian.Uint32(a4[:])
		host := uint32((uint64(1) << (32 - p.Bits())) - 1)
		v |= host
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		out, _ := netip.AddrFromSlice(b[:])
		return out
	}
	raw := p.Addr().As16()
	bits := p.Bits()
	for i := bits; i < 128; i++ {
		raw[i/8] |= 1 << (7 - uint(i%8))
	}
	out, _ := netip.AddrFromSlice(raw[:])
	return out
}

func nextAddr(addr netip.Addr) (netip.Addr, bool) {
	if addr.Is4() {
		a4 := addr.As4()
		v := binary.BigEndian.Uint32(a4[:])
		if v == ^uint32(0) {
			return netip.Addr{}, false
		}
		v++
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		out, _ := netip.AddrFromSlice(b[:])
		return out, true
	}
	raw := addr.As16()
	for i := 15; i >= 0; i-- {
		raw[i]++
		if raw[i] != 0 {
			out, _ := netip.AddrFromSlice(raw[:])
			return out, true
		}
	}
	return netip.Addr{}, false
}

func summarizeRange(first, last netip.Addr) ([]netip.Prefix, error) {
	if first.BitLen() != last.BitLen() || first.Compare(last) > 0 {
		return nil, fmt.Errorf("address family or range order mismatch")
	}
	var out []netip.Prefix
	cur := first
	for {
		maxBits := cur.BitLen()
		bits := maxBits
		for bits > 0 {
			candidate := netip.PrefixFrom(cur, bits-1)
			if candidate.Addr() != candidate.Masked().Addr() {
				break
			}
			if lastAddr(candidate.Masked()).Compare(last) > 0 {
				break
			}
			bits--
		}
		p := netip.PrefixFrom(cur, bits).Masked()
		out = append(out, p)
		end := lastAddr(p)
		if end.Compare(last) >= 0 {
			return out, nil
		}
		next, ok := nextAddr(end)
		if !ok {
			return out, nil
		}
		cur = next
	}
}
