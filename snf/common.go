package snf

import (
	"syscall"
)

import "C"

func retErr(x C.int) error {
	if x < 0 {
		return syscall.Errno(-x)
	} else if x > 0 {
		return syscall.Errno(x)
	}
	return nil
}
