package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sdk"
)

const (
	urMemory   = 48 * 1024 * 1024
	urLocWait  = 10 * time.Second
	urProvWait   = 30 * time.Second
	urShieldWait = 90 * time.Second
)

type urStartRequest struct {
	DataDir       string `json:"data_dir"`
	NetworkJWT    string `json:"network_jwt"`
	ClientJWT     string `json:"client_jwt"`
	InstanceID    string `json:"instance_id"`
	Country       string `json:"country"`
	Strong        *bool  `json:"strong"`
	PostQuantum   bool   `json:"post_quantum"`
	UpstreamSocks string `json:"upstream_socks"`
	SocksPort     int    `json:"socks_port"`
	DeviceModel   string `json:"device_model"`
	Version       string `json:"version"`
}

type urSession struct {
	cancel  context.CancelFunc
	ln      net.Listener
	manager *sdk.NetworkSpaceManager
	device  *sdk.DeviceLocal
}

var (
	urMu      sync.Mutex
	urCurrent *urSession
)

//export PRUrStart
func PRUrStart(requestJSON *C.char) *C.char {
	var req urStartRequest
	if err := json.Unmarshal([]byte(C.GoString(requestJSON)), &req); err != nil {
		return urJSON(false, 0, err.Error())
	}
	port, err := urStart(req)
	if err != nil {
		return urJSON(false, 0, err.Error())
	}
	return urJSON(true, port, "")
}

//export PRUrStop
func PRUrStop() *C.char {
	urStop()
	return urJSON(true, 0, "")
}

//export PRUrFree
func PRUrFree(value *C.char) {
	C.free(unsafe.Pointer(value))
}

//export PRUrIsStub
func PRUrIsStub() C.int {
	return 0
}

func urJSON(ok bool, port int, errText string) *C.char {
	body := map[string]any{"ok": ok}
	if ok && port > 0 {
		body["socks_port"] = port
	}
	if errText != "" {
		body["error"] = errText
	}
	raw, _ := json.Marshal(body)
	return C.CString(string(raw))
}

func urStart(req urStartRequest) (int, error) {
	if strings.TrimSpace(req.DataDir) == "" {
		return 0, fmt.Errorf("data_dir is required")
	}
	if strings.TrimSpace(req.NetworkJWT) == "" || strings.TrimSpace(req.ClientJWT) == "" {
		return 0, fmt.Errorf("URnetwork account is missing")
	}
	if err := os.MkdirAll(req.DataDir, 0o755); err != nil {
		return 0, err
	}
	model := strings.TrimSpace(req.DeviceModel)
	if model == "" {
		model = "iOS"
	}
	version := strings.TrimSpace(req.Version)
	if version == "" {
		version = "26"
	}

	urMu.Lock()
	defer urMu.Unlock()
	if urCurrent != nil {
		return 0, fmt.Errorf("URnetwork is already running")
	}

	sdk.SetUpstreamSocks(strings.TrimSpace(req.UpstreamSocks))
	opened, err := urOpen(req, model, version, strings.TrimSpace(req.UpstreamSocks) != "")
	if err != nil {
		sdk.SetUpstreamSocks("")
		return 0, err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", req.SocksPort))
	if err != nil {
		opened.close()
		sdk.SetUpstreamSocks("")
		return 0, fmt.Errorf("SOCKS listen: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	session := &urSession{cancel: cancel, ln: ln, manager: opened.manager, device: opened.device}
	urCurrent = session
	go urAccept(ctx, ln, opened.device)
	port := ln.Addr().(*net.TCPAddr).Port
	log.Printf("urnetwork socks 127.0.0.1:%d", port)
	return port, nil
}

func urStop() {
	urMu.Lock()
	session := urCurrent
	urCurrent = nil
	urMu.Unlock()
	if session == nil {
		sdk.SetUpstreamSocks("")
		return
	}
	session.cancel()
	_ = session.ln.Close()
	if session.device != nil {
		session.device.Close()
	}
	if session.manager != nil {
		session.manager.Close()
	}
	sdk.SetUpstreamSocks("")
}

func urAccept(ctx context.Context, ln net.Listener, device *sdk.DeviceLocal) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		go func(client net.Conn) {
			defer client.Close()
			_ = urHandleSOCKS(ctx, client, device)
		}(client)
	}
}

type urOpened struct {
	manager *sdk.NetworkSpaceManager
	device  *sdk.DeviceLocal
}

func (o *urOpened) close() {
	if o == nil {
		return
	}
	if o.device != nil {
		o.device.Close()
	}
	if o.manager != nil {
		o.manager.Close()
	}
}

func urOpen(req urStartRequest, model, version string, tcpOnly bool) (*urOpened, error) {
	manager := sdk.NewNetworkSpaceManager(req.DataDir)
	key := sdk.NewNetworkSpaceKey("ur.network", "main")
	space := manager.UpdateNetworkSpace(key, urSpacePatch{})
	manager.SetActiveNetworkSpace(space)
	space.GetApi().SetByJwt(req.NetworkJWT)

	instance, err := urLoadInstance(req.DataDir, req.InstanceID)
	if err != nil {
		manager.Close()
		return nil, err
	}
	local, err := sdk.NewDeviceLocalWithMemoryTarget(
		space,
		req.ClientJWT,
		"PersianRay",
		model,
		version,
		instance,
		false,
		nil,
		urMemory,
	)
	if err != nil {
		manager.Close()
		return nil, err
	}
	// Before any dial. Shield's SOCKS proxy is TCP; Auto would open an H3
	// socket that never enters it. Strong anonymization stays on and
	// post-quantum stays off.
	transport := sdk.DefaultTransportSettings()
	if tcpOnly {
		transport.Mode = sdk.TransportModeH1
	}
	local.SetTransportSettings(transport)
	local.SetProvideMode(sdk.ProvideModeNone)
	local.SetProvideControlMode(sdk.ProvideControlModeNever)

	profile := local.GetPerformanceProfile()
	if profile == nil {
		profile = &sdk.PerformanceProfile{}
	}
	profile.AllowDirect = false
	profile.PostQuantumEncryption = false
	local.SetPerformanceProfile(profile)
	local.SetControlIpFamilyPolicy(sdk.IpFamilyPolicyAuto)
	if dns := sdk.GetDefaultDnsResolverSettings(); dns != nil {
		local.SetDnsResolverSettings(dns)
	}
	local.SetOffline(false)
	local.NetworkChanged()

	location := urBestAvailable()
	country := strings.TrimSpace(req.Country)
	if country != "" {
		location = urCountryLocation(space.GetApi(), country)
	}
	readyCh := make(chan struct{}, 1)
	var accept atomic.Bool
	watch := &urStatusWatch{ch: readyCh, accept: &accept}
	sub := local.AddWindowStatusChangeListener(watch)
	local.SetConnectLocation(location)
	accept.Store(true)
	if urWindowReady(local.GetWindowStatus()) {
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}
	wait := urProvWait
	if tcpOnly {
		wait = urShieldWait
	}
	select {
	case <-readyCh:
		sub.Close()
	case <-time.After(wait):
		sub.Close()
		where := strings.TrimSpace(location.Name)
		if where == "" {
			where = "the best available location"
		}
		local.Close()
		manager.Close()
		return nil, fmt.Errorf("No providers available for %s. Try another location.", where)
	}
	return &urOpened{manager: manager, device: local}, nil
}

type urSpacePatch struct{}

func (urSpacePatch) Update(values *sdk.NetworkSpaceValues) {
	values.Bundled = true
	values.NetExposeServerIps = true
	values.NetExposeServerHostNames = true
	values.LinkHostName = "ur.io"
	values.MigrationHostName = "bringyour.com"
}

func urBestAvailable() *sdk.ConnectLocation {
	return &sdk.ConnectLocation{
		ConnectLocationId: &sdk.ConnectLocationId{BestAvailable: true},
	}
}

func urCountryLocation(api *sdk.Api, code string) *sdk.ConnectLocation {
	type result struct {
		loc *sdk.LocationResult
		err error
	}
	ch := make(chan result, 1)
	api.GetProviderLocations(connect.NewApiCallback(func(found *sdk.FindLocationsResult, err error) {
		var match *sdk.LocationResult
		if err == nil && found != nil && found.Locations != nil {
			list := found.Locations
			for i := 0; i < list.Len(); i++ {
				item := list.Get(i)
				if item == nil {
					continue
				}
				if item.LocationType == sdk.LocationTypeCountry && strings.EqualFold(item.CountryCode, code) {
					match = item
					break
				}
			}
		}
		ch <- result{match, err}
	}))
	select {
	case r := <-ch:
		if r.err != nil || r.loc == nil || r.loc.ProviderCount <= 0 {
			return urBestAvailable()
		}
		return &sdk.ConnectLocation{
			ConnectLocationId: &sdk.ConnectLocationId{LocationId: r.loc.LocationId},
			LocationType:      r.loc.LocationType,
			Name:              r.loc.Name,
			Country:           r.loc.Country,
			CountryCode:       r.loc.CountryCode,
			CountryLocationId: r.loc.CountryLocationId,
			ProviderCount:     int32(r.loc.ProviderCount),
		}
	case <-time.After(urLocWait):
		return urBestAvailable()
	}
}

type urStatusWatch struct {
	ch     chan struct{}
	accept *atomic.Bool
}

func (w *urStatusWatch) WindowStatusChanged(status *sdk.WindowStatus) {
	if w.accept.Load() && urWindowReady(status) {
		select {
		case w.ch <- struct{}{}:
		default:
		}
	}
}

func urWindowReady(status *sdk.WindowStatus) bool {
	return status != nil && (status.ProviderStateAdded > 0 || status.MinSatisfied)
}

func urLoadInstance(dataDir, passed string) (*sdk.Id, error) {
	path := dataDir + string(os.PathSeparator) + "instance-id"
	saved := strings.TrimSpace(passed)
	if raw, err := os.ReadFile(path); err == nil {
		if text := strings.TrimSpace(string(raw)); text != "" {
			saved = text
		}
	}
	var id *sdk.Id
	if saved != "" {
		if parsed, err := sdk.ParseId(saved); err == nil {
			id = parsed
		}
	}
	if id == nil {
		id = sdk.NewId()
	}
	if err := os.WriteFile(path, []byte(id.String()), 0o600); err != nil {
		return nil, err
	}
	return id, nil
}

func urHandleSOCKS(ctx context.Context, client net.Conn, device *sdk.DeviceLocal) error {
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if err := urSocksHandshake(client); err != nil {
		return err
	}
	host, port, err := urSocksConnect(client)
	if err != nil {
		_ = urSocksReply(client, 0x08)
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	remote, err := device.DialContext(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		_ = urSocksReply(client, 0x05)
		return err
	}
	defer remote.Close()
	if err := urSocksReply(client, 0x00); err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(remote, client)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(client, remote)
		errc <- err
	}()
	<-errc
	return nil
}

func urSocksHandshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("not socks5")
	}
	if n := int(buf[1]); n > 0 {
		if _, err := io.ReadFull(conn, make([]byte, n)); err != nil {
			return err
		}
	}
	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

func urSocksConnect(conn net.Conn) (string, int, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", 0, err
	}
	if hdr[0] != 0x05 || hdr[1] != 0x01 {
		return "", 0, fmt.Errorf("unsupported socks command")
	}
	var host string
	switch hdr[3] {
	case 0x01:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return "", 0, err
		}
		host = net.IP(raw).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return "", 0, err
		}
		raw := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(conn, raw); err != nil {
			return "", 0, err
		}
		host = string(raw)
	case 0x04:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return "", 0, err
		}
		host = net.IP(raw).String()
	default:
		return "", 0, fmt.Errorf("unsupported address type")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return "", 0, err
	}
	return host, int(pb[0])<<8 | int(pb[1]), nil
}

func urSocksReply(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
