# psiphon-ios

PersianRay **iOS** fork of the already Edge-Fronting-patched tunnel-core.

Do **not** edit `_psiphon_build/psiphon-tunnel-core` (Android ConsoleClient). This copy is for `PsiphonTunnel.xcframework` only.

## What is already here

Same Domain Fronting knobs as Android:

- `EdgeFrontingDialOverrides` / `SNIServerName`
- `EdgeFrontingScanSpec.IPCandidates`
- `LimitTunnelProtocols` = `FRONTED-MEEK-EDGE-*`

## PersianRay additions (this fork only)

JSON flags on the Psiphon config. **Host lists are not edited here.** On each
connect the iOS app copies `PolicyDomains.swift` / `LocalBypassDomains` into
`PersianRayAdExact`, `PersianRayAdSuffix`, `PersianRayAdult*`, `PersianRayLocalSuffix`,
`PersianRaySafeSearchExact`, `PersianRayDoH*`. Add a domain in Swift and ship an
app release; do not rebuild this xcframework for list updates.

```json
{
  "PersianRayBlockAds": true,
  "PersianRayBlockAdult": true,
  "PersianRaySafeSearch": true,
  "PersianRayBypassLocal": true,
  "SplitTunnelRegions": ["IR"]
}
```

SOCKS and HTTP CONNECT classify the destination **before** meek:

- ads / adult → refuse
- Safe Search hosts → `216.239.38.120` through the tunnel
- local IR suffixes → `DirectDial` (not CDN)

## Build the iOS framework

The Action builds with `PSIPHON_DISABLE_INPROXY` so meek/CDN Fronting does not
pull WebRTC (`pion` / `covert-dtls`). Those packages are not required for PersianRay.

See [BUILD.md](BUILD.md) and the `psiphon-apple` GitHub Action.
