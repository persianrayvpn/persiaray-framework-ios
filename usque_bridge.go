package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	usquemobile "github.com/Diniboy1123/usque/mobile"
)

//export PRUsqueInvoke
func PRUsqueInvoke(requestJSON *C.char) *C.char {
	return C.CString(usquemobile.Invoke(C.GoString(requestJSON)))
}

//export PRUsqueRegister
func PRUsqueRegister(requestJSON *C.char) *C.char {
	return C.CString(usquemobile.Register(C.GoString(requestJSON)))
}

//export PRUsqueStart
func PRUsqueStart(requestJSON *C.char) *C.char {
	return C.CString(usquemobile.Start(C.GoString(requestJSON)))
}

//export PRUsqueStop
func PRUsqueStop(sessionID *C.char) *C.char {
	return C.CString(usquemobile.Stop(C.GoString(sessionID)))
}

//export PRUsqueStopAll
func PRUsqueStopAll() *C.char {
	return C.CString(usquemobile.StopAll())
}

//export PRUsqueStatus
func PRUsqueStatus(sessionID *C.char) *C.char {
	return C.CString(usquemobile.Status(C.GoString(sessionID)))
}

//export PRUsqueIsReady
func PRUsqueIsReady(sessionID *C.char) C.int {
	if usquemobile.IsReady(C.GoString(sessionID)) {
		return 1
	}
	return 0
}

//export PRUsqueLastError
func PRUsqueLastError(sessionID *C.char) *C.char {
	return C.CString(usquemobile.LastError(C.GoString(sessionID)))
}

//export PRUsqueProbe
func PRUsqueProbe(requestJSON *C.char) *C.char {
	return C.CString(usquemobile.Probe(C.GoString(requestJSON)))
}

//export PRUsqueFree
func PRUsqueFree(value *C.char) {
	C.free(unsafe.Pointer(value))
}

//export PRUsqueIsStub
func PRUsqueIsStub() C.int {
	return 0
}
