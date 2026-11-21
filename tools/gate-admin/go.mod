module vpp.local/gate-admin

go 1.24.0

require vpp.local/vpp-egress-gate v0.0.0

require (
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/lunixbochs/struc v0.0.0-20200521075829-a4cb8d33dbbe // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	go.fd.io/govpp v0.13.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

replace vpp.local/vpp-egress-gate => ../vpp-egress-gate
