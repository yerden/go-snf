// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which
// can be found in the LICENSE file in the root of the source
// tree.
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

// Return true if an error is EAGAIN.
func IsEagain(err error) bool {
	return syscall.Errno(syscall.EAGAIN) == err
}

// Return true if an error is EINVAL.
func IsEinval(err error) bool {
	return syscall.Errno(syscall.EINVAL) == err
}

// Return true if an error is ENODEV.
func IsEnodev(err error) bool {
	return syscall.Errno(syscall.ENODEV) == err
}

// Return true if an error is EBUSY.
func IsEbusy(err error) bool {
	return syscall.Errno(syscall.EBUSY) == err
}
