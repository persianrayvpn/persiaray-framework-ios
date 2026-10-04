#!/usr/bin/env bash
# One c-archive: AWG + Xray + Psiphon + USQUE + URnetwork.
# Product name is persianray-core. The clang module stays PersianRayGo so it
# does not collide with the Swift package PersianRayCore.
set -euo pipefail

UNITED=$(cd "$(dirname "$0")/../.." && pwd)
bash "$UNITED/fetch-urnetwork.sh"
AWG="$UNITED/awg-ios"
XRAY="$UNITED/xray-core"
LIBXRAY="$UNITED/libxray"
PSIPHON="$UNITED/psiphon-ios"
USQUE="$UNITED/usque-ios"
if [ ! -d "$PSIPHON" ]; then
  echo "Psiphon source missing. Put psiphon-ios at $UNITED/psiphon-ios" >&2
  exit 1
fi

if [ ! -f "$AWG/cmd/persianray/export.go" ]; then
  echo "bundled awg-ios missing: $AWG/cmd/persianray/export.go" >&2
  exit 1
fi
if [ ! -f "$XRAY/go.mod" ]; then
  echo "bundled xray-core missing: $XRAY/go.mod" >&2
  exit 1
fi
if [ ! -f "$LIBXRAY/go.mod" ]; then
  echo "bundled libxray missing: $LIBXRAY/go.mod" >&2
  exit 1
fi
if [ ! -f "$PSIPHON/MobileLibrary/psi/psi.go" ]; then
  echo "Psiphon iOS bridge source missing: $PSIPHON/MobileLibrary/psi/psi.go" >&2
  exit 1
fi
if [ ! -f "$USQUE/mobile/mobile.go" ]; then
  echo "USQUE iOS adapter source missing: $USQUE/mobile/mobile.go" >&2
  exit 1
fi

echo "==> united=$UNITED"
echo "==> awg-ios=$AWG"
echo "==> xray-core=$XRAY"
echo "==> libxray=$LIBXRAY"
echo "==> psiphon-ios=$PSIPHON"
echo "==> usque-ios=$USQUE"

STAGE="$UNITED/.staging"
rm -rf "$STAGE"
mkdir -p "$STAGE"

cp "$AWG/cmd/persianray/"*.go "$STAGE/"
rm -f "$STAGE/go.mod" "$STAGE/go.sum"
cp "$UNITED/xray_bridge.go" "$STAGE/"
cp "$UNITED/psiphon_bridge.go" "$STAGE/"
cp "$UNITED/usque_bridge.go" "$STAGE/"
cp "$UNITED/urnetwork_bridge.go" "$STAGE/"
cp "$UNITED/go.mod" "$STAGE/"
if [ -f "$UNITED/go.sum" ]; then
  cp "$UNITED/go.sum" "$STAGE/"
fi
# Staged go.mod resolves ./connect-ip-go beside itself.
cp -R "$UNITED/connect-ip-go" "$STAGE/connect-ip-go"

python3 - "$STAGE/go.mod" "$AWG" "$XRAY" "$LIBXRAY" "$PSIPHON" "$USQUE" "$UNITED/urnetwork" <<'PY'
import pathlib, sys
mod = pathlib.Path(sys.argv[1])
awg, xray, libx, psiphon, usque, urn = (pathlib.Path(p).resolve().as_posix() for p in sys.argv[2:])
united = pathlib.Path(urn).parent.as_posix()
text = mod.read_text(encoding="utf-8")
repls = {
    "replace github.com/amnezia-vpn/amneziawg-go/v3 => ./awg-ios":
        f"replace github.com/amnezia-vpn/amneziawg-go/v3 => {awg}",
    "replace github.com/xtls/xray-core => ./xray-core":
        f"replace github.com/xtls/xray-core => {xray}",
    "replace github.com/xtls/libxray => ./libxray":
        f"replace github.com/xtls/libxray => {libx}",
    "replace github.com/Psiphon-Labs/psiphon-tunnel-core => ./psiphon-ios":
        f"replace github.com/Psiphon-Labs/psiphon-tunnel-core => {psiphon}",
    "replace github.com/Psiphon-Labs/quic-go => ./psiphon-ios/vendor/github.com/Psiphon-Labs/quic-go":
        f"replace github.com/Psiphon-Labs/quic-go => {psiphon}/vendor/github.com/Psiphon-Labs/quic-go",
    "replace github.com/Diniboy1123/usque => ./usque-ios":
        f"replace github.com/Diniboy1123/usque => {usque}",
    "replace github.com/Diniboy1123/connect-ip-go => ./connect-ip-go":
        f"replace github.com/Diniboy1123/connect-ip-go => {united}/connect-ip-go",
    "replace github.com/urnetwork/sdk => ./urnetwork/sdk":
        f"replace github.com/urnetwork/sdk => {urn}/sdk",
    "replace github.com/urnetwork/connect => ./urnetwork/connect":
        f"replace github.com/urnetwork/connect => {urn}/connect",
    "replace github.com/urnetwork/glog => ./urnetwork/glog":
        f"replace github.com/urnetwork/glog => {urn}/glog",
    "replace github.com/urnetwork/goidenticons => ./urnetwork/goidenticons":
        f"replace github.com/urnetwork/goidenticons => {urn}/goidenticons",
    "replace github.com/pion/sctp => ./urnetwork/connect/sctp":
        f"replace github.com/pion/sctp => {urn}/connect/sctp",
}
for old, new in repls.items():
    if old not in text:
        raise SystemExit(f"go.mod missing line: {old}")
    text = text.replace(old, new)
mod.write_text(text, encoding="utf-8")
PY

cd "$STAGE"
go mod edit -go=1.26.3

# Same quic-go patch Android and Tauri apply. Without it, USQUE_QUIC_SPLIT
# and USQUE_QUIC_REORDER are ignored and those UDP presets do nothing.
echo "==> patching quic-go for MASQUE UDP split and reorder"
QUIC_VER="$(go list -m -f '{{.Version}}' github.com/quic-go/quic-go)"
go mod download "github.com/quic-go/quic-go@${QUIC_VER}"
MODCACHE="$(go env GOMODCACHE)"
SRC="${MODCACHE}/github.com/quic-go/quic-go@${QUIC_VER}"
DST="${TMPDIR:-/tmp}/persianray-quic-go-${QUIC_VER}"
rm -rf "$DST"
cp -a "$SRC" "$DST"
chmod -R u+w "$DST"
python3 "$USQUE/patch-quic-initial.py" "$DST"
go mod edit -replace "github.com/quic-go/quic-go=${DST}"

MIN=15.0
OUT="$UNITED/build"
rm -rf "$OUT"
mkdir -p "$OUT/ios-arm64" "$OUT/ios-arm64-simulator"

export CGO_ENABLED=1

build_one() {
  local sdk="$1" arch="$2" dir="$3" minflag="$4"
  local sysroot cc
  sysroot=$(xcrun --sdk "$sdk" --show-sdk-path)
  cc=$(xcrun --sdk "$sdk" -f clang)
  echo "==> $sdk $arch"
  GOOS=ios GOARCH="$arch" \
    CC="$cc" \
    CGO_CFLAGS="-isysroot $sysroot $minflag -arch $arch" \
    CGO_LDFLAGS="-isysroot $sysroot $minflag -arch $arch" \
    go build -mod=mod -tags PSIPHON_DISABLE_INPROXY -buildmode=c-archive -trimpath -ldflags "-s -w" \
      -o "$dir/libpersianraycore.a" .
}

build_one iphoneos arm64 "$OUT/ios-arm64" "-miphoneos-version-min=$MIN"
build_one iphonesimulator arm64 "$OUT/ios-arm64-simulator" "-mios-simulator-version-min=$MIN"

install_headers() {
  local dest="$1/Headers"
  mkdir -p "$dest"
  cp "$UNITED/include/libawgxray.h" "$dest/"
  cp "$UNITED/include/liburnetwork.h" "$dest/"
  cp "$UNITED/include/libawg.h" "$dest/"
  cp "$UNITED/include/libxray.h" "$dest/"
  cp "$UNITED/include/libusque.h" "$dest/"
  cp "$UNITED/include/module.modulemap" "$dest/"
}

install_headers "$OUT/ios-arm64"
install_headers "$OUT/ios-arm64-simulator"

xcodebuild -create-xcframework \
  -library "$OUT/ios-arm64/libpersianraycore.a" -headers "$OUT/ios-arm64/Headers" \
  -library "$OUT/ios-arm64-simulator/libpersianraycore.a" -headers "$OUT/ios-arm64-simulator/Headers" \
  -output "$OUT/persianray-core.xcframework"

echo "==> $OUT/persianray-core.xcframework"
echo "Copy to persianray-ios/Vendor/persianray-core/persianray-core.xcframework"
