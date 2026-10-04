package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

func cErr(err error) *C.char {
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}

func goStr(p *C.char) string {
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

//export AwgStart
func AwgStart(configJSON *C.char) *C.char {
	cfg, err := parseConfigJSON([]byte(goStr(configJSON)))
	if err != nil {
		return cErr(err)
	}
	if err := startLive(cfg); err != nil {
		return cErr(err)
	}
	return nil
}

//export AwgStop
func AwgStop() *C.char {
	stopLive()
	return nil
}

//export AwgSetHopInner
func AwgSetHopInner(endpoint *C.char) *C.char {
	if err := setLiveHopInner(goStr(endpoint)); err != nil {
		return cErr(err)
	}
	return nil
}

//export AwgPing
func AwgPing(requestJSON *C.char) *C.char {
	out, err := runPing([]byte(goStr(requestJSON)))
	if err != nil {
		return C.CString(`{"error":` + jsonQuote(err.Error()) + `}`)
	}
	return C.CString(string(out))
}

//export AwgAdBlockTake
func AwgAdBlockTake() C.longlong {
	return C.longlong(adBlockPending.Swap(0))
}

//export AwgFree
func AwgFree(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

//export AwgIsStub
func AwgIsStub() C.int {
	return 0
}

func jsonQuote(s string) string {
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\', '"':
			b = append(b, '\\', c)
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		default:
			b = append(b, c)
		}
	}
	b = append(b, '"')
	return string(b)
}

func main() {}
