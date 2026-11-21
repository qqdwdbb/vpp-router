package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

// offeredExit is one line of the file gate-admin reads to offer exits, in the format
// vpp-wireguard also writes. An interface with a static gateway is an exit like any other;
// one on DHCP has a next hop only Gate can read at run time, from the lease, so it can carry
// only the default route.
type offeredExit struct {
	Interface string `json:"interface"`
	Via       string `json:"via,omitempty"`
	DHCP      bool   `json:"dhcp,omitempty"`
}

// fileExits lists the interfaces the CLI file gives a default route: the static gateways,
// then DHCP, in file order.
func fileExits(file *cliFile) []offeredExit {
	exits := []offeredExit{}
	for _, line := range file.lines {
		if line.kind == lineGateway && line.via.IsValid() {
			exits = append(exits, offeredExit{Interface: line.iface, Via: line.via.String()})
		}
	}
	for _, line := range file.lines {
		if line.kind == lineDHCP4 {
			exits = append(exits, offeredExit{Interface: line.iface, DHCP: true})
		}
	}
	return exits
}

// publishExits writes the exits of the CLI file as it is now. It runs at startup and after
// every change to the file. A failure costs gate-admin choices, so it is only logged.
func (s *Service) publishExits() {
	if s.opts.ExitsFile == "" {
		return
	}
	file, err := s.load()
	if err == nil {
		var data []byte
		if data, err = json.Marshal(fileExits(file)); err == nil {
			if err = os.MkdirAll(filepath.Dir(s.opts.ExitsFile), 0o700); err == nil {
				err = writeFileAtomic(s.opts.ExitsFile, append(data, '\n'), 0o644)
			}
		}
	}
	if err != nil {
		log.Printf("publishing the exits: %v", err)
	}
}
