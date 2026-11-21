package main

import (
	"os"
	"syscall"
)

// fileStamp tells one VPP run from the next by its socket file.
type fileStamp struct {
	Ino   uint64
	Ctime int64
}

func stampOf(path string) (fileStamp, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return fileStamp{}, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	return fileStamp{Ino: st.Ino, Ctime: st.Ctim.Nano()}, nil
}
