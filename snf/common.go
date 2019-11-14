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

/*
#cgo CFLAGS: -I/opt/snf/include
#cgo LDFLAGS: -L/opt/snf/lib -lsnf -lpcap
#include <snf.h>
#include "wrapper.h"
*/
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

func intErr(out *C.struct_compound_int) (int, error) {
	return int(*(*C.int)(unsafe.Pointer(out))), retErr(out.rc)
}

func uint64Err(out *C.struct_compound_int) (uint64, error) {
	return uint64(*(*C.ulong)(unsafe.Pointer(out))), retErr(out.rc)
}
