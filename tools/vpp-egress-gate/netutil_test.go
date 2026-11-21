package gate

import (
	"net/netip"
	"testing"
)

func TestSummarizeRange(t *testing.T) {
	first, _ := netip.ParseAddr("198.51.100.0")
	last, _ := netip.ParseAddr("198.51.100.3")
	got, err := summarizeRange(first, last)
	if err != nil || len(got) != 1 || got[0].String() != "198.51.100.0/30" {
		t.Fatalf("got %v, %v", got, err)
	}
	first, _ = netip.ParseAddr("203.0.114.1")
	last, _ = netip.ParseAddr("203.0.114.3")
	got, err = summarizeRange(first, last)
	if err != nil || len(got) != 2 || got[0].String() != "203.0.114.1/32" || got[1].String() != "203.0.114.2/31" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestExcludePrefix(t *testing.T) {
	whole, _ := netip.ParsePrefix("192.0.2.0/24")
	sub, _ := netip.ParsePrefix("192.0.2.64/26")
	got := excludePrefix(whole, sub)
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestPrefixIndexAddDeduplicates(t *testing.T) {
	idx := NewPrefixIndex()
	n := netip.MustParsePrefix("198.51.100.77/32")
	key := RouteKey{0, n.String()}
	idx.Add(n, key, 0)
	idx.Add(n, key, 0)
	idx.Add(n, key, 0)
	got := idx.Covering(n, 0)
	if len(got) != 1 {
		t.Fatalf("covering %d, want 1", len(got))
	}
}
