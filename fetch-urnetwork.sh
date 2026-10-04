#!/usr/bin/env bash
# Downloads the URnetwork trees this core links, then applies the Shield dial
# patch. Runs on the GitHub macOS runner. Nothing here is cloned on Windows.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
DEST="$ROOT/urnetwork"
OVERLAY="$ROOT/urnetwork-overlay"

SDK_SHA=40432c72288d8dce09a68622ee7afff90925f80a
CONNECT_SHA=44d007e48cb3b26f17e3b9d4690fe1c2046b7106
GLOG_SHA=80a11b434ae90ae2221deb932daa21913919875a
ICONS_SHA=325750b38314313dc5f44c880ab6f12f6c1ecb3c

fetch_sha() {
  local url="$1" sha="$2" dir="$3"
  if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse HEAD)" = "$sha" ]; then
    return
  fi
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$dir" init
  git -C "$dir" remote add origin "$url"
  git -C "$dir" fetch --depth 1 origin "$sha"
  git -C "$dir" checkout --detach FETCH_HEAD
}

mkdir -p "$DEST"
fetch_sha https://github.com/urnetwork/sdk.git "$SDK_SHA" "$DEST/sdk"
fetch_sha https://github.com/urnetwork/connect.git "$CONNECT_SHA" "$DEST/connect"
fetch_sha https://github.com/urnetwork/glog.git "$GLOG_SHA" "$DEST/glog"
fetch_sha https://github.com/urnetwork/goidenticons.git "$ICONS_SHA" "$DEST/goidenticons"

# macOS BSD patch rejects these hunks when the file has a UTF-8 BOM or CR.
# git apply accepts the same diff after that noise is stripped.
apply_overlay() {
  local dir="$1" src="$2" normalized
  normalized=$(mktemp)
  perl -pe 's/^\xEF\xBB\xBF//; s/\r$//' "$src" > "$normalized"
  git -C "$dir" apply --whitespace=nowarn "$normalized"
  rm -f "$normalized"
}

if ! grep -q 'func SetUpstreamSocks' "$DEST/sdk/sdk.go"; then
  apply_overlay "$DEST/sdk" "$OVERLAY/sdk.patch"
fi
if [ ! -f "$DEST/connect/upstream_socks.go" ]; then
  apply_overlay "$DEST/connect" "$OVERLAY/connect.patch"
fi
cp "$OVERLAY/upstream_socks.go" "$DEST/connect/upstream_socks.go"

# quic-go v0.61 removed http3.ParseCapsule. connect-ip-go still calls it.
# Copy the module and switch that one call to CapsuleParser.Next.
CIP_VER=v0.0.0-20260613064811-66cba32d7d33
CIP_DST="$ROOT/connect-ip-go"
CIP_SRC=$(go mod download -json "github.com/Diniboy1123/connect-ip-go@${CIP_VER}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])')
rm -rf "$CIP_DST"
cp -R "$CIP_SRC" "$CIP_DST"
chmod -R u+w "$CIP_DST"
python3 - "$CIP_DST/conn.go" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = "\tr := quicvarint.NewReader(c.str)\n\tfor {\n\t\tt, cr, err := http3.ParseCapsule(r)\n"
new = "\tparser := http3.NewCapsuleParser(c.str)\n\tfor {\n\t\tt, cr, err := parser.Next()\n"
if old not in text:
    raise SystemExit("connect-ip-go conn.go no longer matches the ParseCapsule patch")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
echo "==> urnetwork sources at $DEST"
