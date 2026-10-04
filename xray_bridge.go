package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	libXray "github.com/xtls/libxray"
)

// Same C ABI as XTLS/libXray cgo_bridge. Do not rename.

//export CGoInvoke
func CGoInvoke(requestJSON *C.char) *C.char {
	return C.CString(libXray.Invoke(C.GoString(requestJSON)))
}

//export CGoFree
func CGoFree(value *C.char) {
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}

//export LibXrayIsStub
func LibXrayIsStub() C.int {
	return 0
}
