# ios-awg-xray

One iOS `c-archive` with AWG, Xray, Psiphon, and USQUE C ABIs in **one Go runtime**. Engines are vendored in this folder; builds do not run git.

| Path | What |
| --- | --- |
| `awg-ios/` | Full Amnezia + `cmd/persianray` (copied from repo `awg-ios`) |
| `xray-core/` | Local Xray-core (copied from `PersianRay/xray/.work-xray` — your checkout, including any patches) |
| `libxray/` | XTLS/libXray **v26.7.28** C `Invoke` wrapper, `replace`d onto `../xray-core` |
| `psiphon-ios/` | Complete customized Psiphon source and vendored dependencies, including the PersianRay policy and QUIC compatibility patches |
| `usque-ios/` | Local USQUE source plus the session-safe `mobile` adapter |
| `xray_bridge.go` | `CGoInvoke` / `CGoFree` / `LibXrayIsStub` |
| `usque_bridge.go` | `PRUsque*` C exports |

C ABI includes `Awg*`, `CGoInvoke`, `PRPsiphon*`, and `PRUsque*`. Do not also link any standalone engine framework.

## USQUE native contract

Every returned `char *` is UTF-8 JSON and must be released with `PRUsqueFree`.
Responses are `{"ok":true,"id":"...","data":...}` or
`{"ok":false,"id":"...","error":"..."}`.

- `PRUsqueInvoke(request)`: compatibility dispatcher used by the existing
  Swift runtime. It supports `register`, `start`, `setHopRelay`, `stop`,
  `abortProbes`, and short-lived `probe` requests. A probe establishes
  CONNECT-IP, then requires HTTP 204 from
  `http://www.gstatic.com/generate_204` through the session netstack; `warmup`
  discards the first successful HTTP request. Config-file persistence and the
  raw UDP relay used by an inner WireGuard hop are also included.
- `PRUsqueRegister(request)`: registers and enrolls a MASQUE key. The request
  accepts `model`, `locale`, `device_name`, `jwt`, and mandatory
  `accept_tos:true`; the response contains `data.config`.
- `PRUsqueStart(request)`: starts an independent session. Required:
  `config` from registration. Options: caller-selected `id`, `transport`
  (`h3`, UDP, default; or `h2`, TCP), `use_ipv6`, `connect_port`, loopback
  `bind`, `socks_port` (`0` chooses a free port), SOCKS credentials, `dns`,
  `mtu`, keepalive/reconnect/UDP timeout values. Endpoint public-key pinning is
  enabled by default; `insecure:true` explicitly disables it.
  The returned SOCKS5 endpoint supports CONNECT and UDP ASSOCIATE.
- `PRUsqueStatus(id)` / `PRUsqueIsReady(id)` /
  `PRUsqueLastError(id)`: report readiness and errors. `ready` means a real
  CONNECT-IP handshake completed.
- `PRUsqueProbe(request)`: makes a real tunneled `tcp` or `udp` dial to
  `address`. Optional `payload_base64` writes and reads one response; optional
  `timeout_millis` defaults to 5000.
- `PRUsqueStop(id)` / `PRUsqueStopAll()`: cancel transport, listeners, virtual
  stack, and UDP relays.

The adapter does not call Cobra or mutate USQUE's `config.AppConfig`. Each
session owns its context, netstack, SOCKS listener, errors, and UDP flow map.
There is no MASQUE spoof/desync behavior.

## Build (macOS)

```bash
chmod +x MobileLibrary/iOS/build-awg-xray-framework.sh
./MobileLibrary/iOS/build-awg-xray-framework.sh
# → build/persianray-core.xcframework
```

The script downloads URnetwork on the build machine, then links it into the
same archive as AWG, Xray, Psiphon, and USQUE. The clang module is
`PersianRayGo`. The Swift package `PersianRayCore` is a different target.

GitHub Action: `awg-xray-apple` (`workflow_dispatch`). It uploads
`persianray-core.xcframework`. Drop that artifact at
`persianray-ios/Vendor/persianray-core/persianray-core.xcframework`.

`go.mod` uses a local `replace` for USQUE. gVisor remains replaced to the
unified Amnezia-compatible revision, while module selection reconciles the
newer WireGuard dependency needed by USQUE.
