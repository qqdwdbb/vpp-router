// Offline cache migration for sing-box 1.14.3. Stop sing-box and back up first.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	bolt "github.com/sagernet/bbolt"
)

var oldPool = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
var newPool = netip.MustParsePrefix("2001:2::/48")

func translate(address netip.Addr) (netip.Addr, error) {
	if !oldPool.Contains(address) {
		return netip.Addr{}, fmt.Errorf("unexpected IPv6 mapping outside old pool")
	}
	raw := address.As16()
	prefix := newPool.Addr().As16()
	copy(raw[:6], prefix[:6])
	return netip.AddrFrom16(raw), nil
}

func migrate(tx *bolt.Tx) error {
	addresses := tx.Bucket([]byte("fakeip_address"))
	if addresses == nil {
		return fmt.Errorf("missing fakeip_address bucket")
	}
	key := []byte("fakeip_metadata")
	reader := bytes.NewReader(addresses.Get(key))
	fields := make([][]byte, 4)
	for i := range fields {
		var length uint16
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return err
		}
		fields[i] = make([]byte, length)
		if _, err := io.ReadFull(reader, fields[i]); err != nil {
			return err
		}
	}
	if reader.Len() != 0 {
		return fmt.Errorf("unexpected metadata format")
	}
	var pool4, pool6 netip.Prefix
	var current4, current6 netip.Addr
	if err := pool4.UnmarshalBinary(fields[0]); err != nil {
		return err
	}
	if err := pool6.UnmarshalBinary(fields[1]); err != nil {
		return err
	}
	if err := current4.UnmarshalBinary(fields[2]); err != nil {
		return err
	}
	if err := current6.UnmarshalBinary(fields[3]); err != nil {
		return err
	}
	if pool4 != netip.MustParsePrefix("198.18.0.0/15") || pool6 != oldPool {
		return fmt.Errorf("unexpected cache pools")
	}
	next6, err := translate(current6)
	if err != nil {
		return err
	}
	fields[1], _ = newPool.MarshalBinary()
	fields[3], _ = next6.MarshalBinary()
	type entry struct{ key, value []byte }
	var moves []entry
	err = addresses.ForEach(func(k, v []byte) error {
		if len(k) == 16 {
			moves = append(moves, entry{bytes.Clone(k), bytes.Clone(v)})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, item := range moves {
		address, ok := netip.AddrFromSlice(item.key)
		if !ok {
			return fmt.Errorf("invalid mapping key")
		}
		translated, err := translate(address)
		if err != nil {
			return err
		}
		if err := addresses.Delete(item.key); err != nil {
			return err
		}
		if err := addresses.Put(translated.AsSlice(), item.value); err != nil {
			return err
		}
	}
	domains := tx.Bucket([]byte("fakeip_domain6"))
	var domainMoves []entry
	if domains != nil {
		err = domains.ForEach(func(k, v []byte) error {
			domainMoves = append(domainMoves, entry{bytes.Clone(k), bytes.Clone(v)})
			return nil
		})
		if err != nil {
			return err
		}
		for _, item := range domainMoves {
			address, ok := netip.AddrFromSlice(item.value)
			if !ok {
				return fmt.Errorf("invalid reverse mapping")
			}
			translated, err := translate(address)
			if err != nil {
				return err
			}
			if !bytes.Equal(addresses.Get(translated.AsSlice()), item.key) {
				return fmt.Errorf("inconsistent reverse mapping")
			}
			if err := domains.Put(item.key, translated.AsSlice()); err != nil {
				return err
			}
		}
	}
	var metadata bytes.Buffer
	for _, field := range fields {
		if err := binary.Write(&metadata, binary.BigEndian, uint16(len(field))); err != nil {
			return err
		}
		metadata.Write(field)
	}
	if err := addresses.Put(key, metadata.Bytes()); err != nil {
		return err
	}
	fmt.Printf("migrated IPv6 mappings=%d reverse mappings=%d; IPv4 mappings retained\n", len(moves), len(domainMoves))
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: cache-migrate STOPPED_CACHE_DB")
		os.Exit(2)
	}
	db, err := bolt.Open(os.Args[1], 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		panic(err)
	}
	defer db.Close()
	if err := db.Update(migrate); err != nil {
		panic(err)
	}
}
