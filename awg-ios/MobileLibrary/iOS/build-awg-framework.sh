#!/usr/bin/env bash
# Build Awg.xcframework (c-archive) for iOS device + simulator.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT/cmd/persianray"

echo "==> go mod download (cmd/persianray)"
go mod download

MIN=15.0
OUT="$ROOT/build"
rm -rf "$OUT"
mkdir -p "$OUT/ios-arm64" "$OUT/ios-arm64-simulator"

export CGO_ENABLED=1

build_one() {
  local sdk="$1" arch="$2" dir="$3" minflag="$4"
  local sysroot
  sysroot=$(xcrun --sdk "$sdk" --show-sdk-path)
  local cc
  cc=$(xcrun --sdk "$sdk" -f clang)
  echo "==> $sdk $arch"
  GOOS=ios GOARCH="$arch" \
    CC="$cc" \
    CGO_CFLAGS="-isysroot $sysroot $minflag -arch $arch" \
    CGO_LDFLAGS="-isysroot $sysroot $minflag -arch $arch" \
    go build -buildmode=c-archive -trimpath -ldflags "-s -w" \
      -o "$dir/libawg.a" .
}

build_one iphoneos arm64 "$OUT/ios-arm64" "-miphoneos-version-min=$MIN"
build_one iphonesimulator arm64 "$OUT/ios-arm64-simulator" "-mios-simulator-version-min=$MIN"

mkdir -p "$OUT/ios-arm64/Headers" "$OUT/ios-arm64-simulator/Headers"
cp "$OUT/ios-arm64/libawg.h" "$OUT/ios-arm64/Headers/libawg.h"
cp "$OUT/ios-arm64-simulator/libawg.h" "$OUT/ios-arm64-simulator/Headers/libawg.h"
printf 'module Awg {\n  header "libawg.h"\n  export *\n}\n' > "$OUT/ios-arm64/Headers/module.modulemap"
cp "$OUT/ios-arm64/Headers/module.modulemap" "$OUT/ios-arm64-simulator/Headers/module.modulemap"

xcodebuild -create-xcframework \
  -library "$OUT/ios-arm64/libawg.a" -headers "$OUT/ios-arm64/Headers" \
  -library "$OUT/ios-arm64-simulator/libawg.a" -headers "$OUT/ios-arm64-simulator/Headers" \
  -output "$OUT/Awg.xcframework"

echo "==> $OUT/Awg.xcframework"
