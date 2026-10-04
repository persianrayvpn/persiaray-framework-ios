package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"sync"
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
)

const maxPsiphonNotices = 512

type psiphonProvider struct{}

var psiphonBridge = struct {
	sync.Mutex
	notices   []string
	socksPort int
	httpPort  int
	connected bool
}{}

func (psiphonProvider) Notice(noticeJSON string) {
	psiphonBridge.Lock()
	defer psiphonBridge.Unlock()

	var notice struct {
		NoticeType string `json:"noticeType"`
		Data       struct {
			Count int `json:"count"`
			Port  int `json:"port"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(noticeJSON), &notice) == nil {
		switch notice.NoticeType {
		case "Tunnels":
			psiphonBridge.connected = notice.Data.Count > 0
		case "ListeningSocksProxyPort":
			psiphonBridge.socksPort = notice.Data.Port
		case "ListeningHttpProxyPort":
			psiphonBridge.httpPort = notice.Data.Port
		case "Exiting":
			psiphonBridge.connected = false
		}
	}

	if len(psiphonBridge.notices) == maxPsiphonNotices {
		copy(psiphonBridge.notices, psiphonBridge.notices[1:])
		psiphonBridge.notices[len(psiphonBridge.notices)-1] = noticeJSON
		return
	}
	psiphonBridge.notices = append(psiphonBridge.notices, noticeJSON)
}

func (psiphonProvider) HasNetworkConnectivity() int  { return 1 }
func (psiphonProvider) GetNetworkID() string         { return "UNKNOWN" }
func (psiphonProvider) IPv6Synthesize(string) string { return "" }
func (psiphonProvider) HasIPv6Route() int            { return 0 }
func (psiphonProvider) GetDNSServersAsString() string {
	return ""
}
func (psiphonProvider) BindToDevice(int) (string, error) {
	return "", errors.New("BindToDevice is not supported on iOS")
}

func resetPsiphonBridgeState() {
	psiphonBridge.Lock()
	psiphonBridge.notices = nil
	psiphonBridge.socksPort = 0
	psiphonBridge.httpPort = 0
	psiphonBridge.connected = false
	psiphonBridge.Unlock()
}

//export PRPsiphonStart
func PRPsiphonStart(configJSON, embeddedServerList *C.char) *C.char {
	// Drop a leftover controller or notice writer from an earlier attempt
	// in this process before installing a new one.
	psi.Stop()
	resetPsiphonBridgeState()
	err := psi.Start(
		C.GoString(configJSON),
		C.GoString(embeddedServerList),
		"",
		psiphonProvider{},
		false,
		false,
		false,
	)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export PRPsiphonStop
func PRPsiphonStop() {
	psi.Stop()
	resetPsiphonBridgeState()
}

//export PRPsiphonNoticePoll
func PRPsiphonNoticePoll() *C.char {
	psiphonBridge.Lock()
	defer psiphonBridge.Unlock()
	if len(psiphonBridge.notices) == 0 {
		return nil
	}
	notice := psiphonBridge.notices[0]
	psiphonBridge.notices = psiphonBridge.notices[1:]
	return C.CString(notice)
}

//export PRPsiphonSocksPort
func PRPsiphonSocksPort() C.int {
	psiphonBridge.Lock()
	defer psiphonBridge.Unlock()
	return C.int(psiphonBridge.socksPort)
}

//export PRPsiphonHTTPPort
func PRPsiphonHTTPPort() C.int {
	psiphonBridge.Lock()
	defer psiphonBridge.Unlock()
	return C.int(psiphonBridge.httpPort)
}

//export PRPsiphonIsConnected
func PRPsiphonIsConnected() C.int {
	psiphonBridge.Lock()
	defer psiphonBridge.Unlock()
	if psiphonBridge.connected {
		return 1
	}
	return 0
}

//export PRPsiphonFree
func PRPsiphonFree(value *C.char) {
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}

//export PRPsiphonIsStub
func PRPsiphonIsStub() C.int {
	return 0
}
