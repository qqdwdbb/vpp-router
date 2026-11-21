//go:build linux

package gate

import "syscall"

func mtimeNano(st *syscall.Stat_t) int64 { return st.Mtim.Nano() }
func ctimeNano(st *syscall.Stat_t) int64 { return st.Ctim.Nano() }
