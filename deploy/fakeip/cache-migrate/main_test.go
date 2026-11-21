package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"testing"

	bolt "github.com/sagernet/bbolt"
)

func TestMigrationPreservesIPv4AndTranslatesIPv6(t *testing.T) {
	db, err := bolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v4 := netip.MustParseAddr("198.18.0.22").AsSlice()
	v6 := netip.MustParseAddr("fd7a:115c:a1e0::23").AsSlice()
	err = db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucket([]byte("fakeip_address"))
		d4, _ := tx.CreateBucket([]byte("fakeip_domain4"))
		d6, _ := tx.CreateBucket([]byte("fakeip_domain6"))
		b.Put(v4, []byte("v4.example"))
		b.Put(v6, []byte("v6.example"))
		d4.Put([]byte("v4.example"), v4)
		d6.Put([]byte("v6.example"), v6)
		fields := make([][]byte, 4)
		fields[0], _ = netip.MustParsePrefix("198.18.0.0/15").MarshalBinary()
		fields[1], _ = oldPool.MarshalBinary()
		fields[2], _ = netip.MustParseAddr("198.18.0.22").MarshalBinary()
		fields[3], _ = netip.MustParseAddr("fd7a:115c:a1e0::23").MarshalBinary()
		var metadata bytes.Buffer
		for _, field := range fields {
			binary.Write(&metadata, binary.BigEndian, uint16(len(field)))
			metadata.Write(field)
		}
		return b.Put([]byte("fakeip_metadata"), metadata.Bytes())
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(migrate); err != nil {
		t.Fatal(err)
	}
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("fakeip_address"))
		translated := netip.MustParseAddr("2001:2::23").AsSlice()
		if string(b.Get(v4)) != "v4.example" || string(b.Get(translated)) != "v6.example" || b.Get(v6) != nil {
			t.Fatal("bad address mappings")
		}
		if !bytes.Equal(tx.Bucket([]byte("fakeip_domain4")).Get([]byte("v4.example")), v4) {
			t.Fatal("IPv4 mapping changed")
		}
		if !bytes.Equal(tx.Bucket([]byte("fakeip_domain6")).Get([]byte("v6.example")), translated) {
			t.Fatal("bad IPv6 reverse mapping")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A second invocation must fail without committing any changes.
	if err := db.Update(migrate); err == nil {
		t.Fatal("accepted already migrated metadata")
	}
}
