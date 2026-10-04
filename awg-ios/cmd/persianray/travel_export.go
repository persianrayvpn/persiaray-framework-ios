package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
)

// PRTravelPick probes NAT64 gateways through a local SOCKS5 (the MASQUE hop's
// usque) and returns {"targets":[{"host","country","label"}]}, fastest first.
// Request: {"socks_port":10809,"countries":["US"]}. Free with PRTravelFree.
//
//export PRTravelPick
func PRTravelPick(requestJSON *C.char) *C.char {
	var req struct {
		SocksPort int      `json:"socks_port"`
		Countries []string `json:"countries"`
	}
	if err := json.Unmarshal([]byte(goStr(requestJSON)), &req); err != nil {
		return C.CString(`{"error":` + jsonQuote(err.Error()) + `}`)
	}
	countries := travelNormalizeCountries(req.Countries)
	targets := []travelHost{}
	if req.SocksPort > 0 && len(countries) > 0 {
		if picked := travelPickTargets(travelSocksDial(req.SocksPort), countries); picked != nil {
			targets = picked
		}
	}
	out, _ := json.Marshal(map[string]any{"targets": targets})
	return C.CString(string(out))
}

// PRTravelLogTake returns and clears the Travel Mode log lines ("\n"-joined).
//
//export PRTravelLogTake
func PRTravelLogTake() *C.char {
	return C.CString(travelLogTake())
}

//export PRTravelFree
func PRTravelFree(p *C.char) {
	AwgFree(p)
}
