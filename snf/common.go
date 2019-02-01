package snf

import (
	"reflect"
	"syscall"
	"unsafe"
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

func array2Slice(ptr uintptr, length int) (data []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = ptr
	sh.Len = length
	sh.Cap = length
	return
}
