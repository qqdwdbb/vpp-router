package main

import (
	"log"
	"os"

	gate "vpp.local/vpp-egress-gate"
)

func main() {
	if err := gate.Run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
