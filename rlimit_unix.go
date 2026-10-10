//go:build !windows

package main

import "syscall"

// raiseFileLimit lifts the soft open-file limit so high scan concurrency
// (thousands of sockets in flight) does not hit "too many open files".
func raiseFileLimit() {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return
	}
	const want = 10240
	if rl.Cur >= want {
		return
	}
	if rl.Max < want {
		rl.Cur = rl.Max
	} else {
		rl.Cur = want
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl)
}
