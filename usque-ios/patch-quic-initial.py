"""Optional quic-go client patches, applied to a temporary copy.

USQUE_QUIC_SPLIT=1 caps the first Initial CRYPTO frame. Unset, packing
is unchanged.

USQUE_QUIC_REORDER=1 sends the ClientHello bytes from the middle of the
hostname through the end before the earlier bytes. Each of those CRYPTO
frames goes in its own Initial packet. Unset, quic-go's own order remains.

USQUE_H3_MAX_UDP_PAYLOAD, when set to 1200..1452, is advertised as the
client max_udp_payload_size. Unset, the client still advertises 1452.
The server transport parameters are not modified.
"""
import pathlib
import sys

def patch_initial_split(root: pathlib.Path) -> None:
    p = root / "packet_packer.go"
    text = p.read_text(encoding="utf-8")
    if "USQUE_QUIC_SPLIT" in text:
        print("already patched", p)
        return
    old_imp = '\t"math/rand/v2"\n'
    if old_imp not in text:
        raise SystemExit("import anchor missing")
    text = text.replace(old_imp, old_imp + '\t"os"\n', 1)
    old_field = "\tnumNonAckElicitingAcks int\n}"
    new_field = (
        "\tnumNonAckElicitingAcks int\n"
        "\tsplitInitial           bool\n"
        "\tdidSplitInitial        bool\n"
        "\treorderInitial         bool\n}"
    )
    if old_field not in text:
        raise SystemExit("field anchor missing")
    text = text.replace(old_field, new_field, 1)
    old_rand = (
        "\t\trand:                *rand.New(rand.NewPCG("
        "binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:]))),\n"
    )
    if old_rand not in text:
        raise SystemExit("ctor anchor missing")
    text = text.replace(
        old_rand,
        old_rand
        + '\t\tsplitInitial:         os.Getenv("USQUE_QUIC_SPLIT") == "1",\n'
        + '\t\treorderInitial:       os.Getenv("USQUE_QUIC_REORDER") == "1",\n',
        1,
    )
    old_loop = "\t\tfor hasCryptoData() {\n\t\t\tcf := popCryptoFrame(maxPacketSize)\n"
    new_loop = (
        "\t\tfor hasCryptoData() {\n"
        "\t\t\tcryptoMax := maxPacketSize\n"
        "\t\t\tsplitThis := p.splitInitial && encLevel == protocol.EncryptionInitial && !p.didSplitInitial\n"
        "\t\t\tif splitThis && cryptoMax > 200 {\n"
        "\t\t\t\tcryptoMax = 200\n"
        "\t\t\t}\n"
        "\t\t\tcf := popCryptoFrame(cryptoMax)\n"
        "\t\t\tif splitThis {\n"
        "\t\t\t\tp.didSplitInitial = true\n"
        "\t\t\t}\n"
    )
    if old_loop not in text:
        raise SystemExit("loop anchor missing")
    text = text.replace(old_loop, new_loop, 1)
    old_tail = (
        "\t\t\tpl.length += cf.Length(v)\n"
        "\t\t\tmaxPacketSize -= cf.Length(v)\n"
        "\t\t}\n"
    )
    count = text.count(old_tail)
    if count != 1:
        raise SystemExit(f"tail anchor count {count}, want 1")
    new_tail = (
        "\t\t\tpl.length += cf.Length(v)\n"
        "\t\t\tmaxPacketSize -= cf.Length(v)\n"
        "\t\t\tif splitThis || (p.reorderInitial && encLevel == protocol.EncryptionInitial) {\n"
        "\t\t\t\tbreak\n"
        "\t\t\t}\n"
        "\t\t}\n"
    )
    text = text.replace(old_tail, new_tail, 1)
    p.write_text(text, encoding="utf-8", newline="\n")
    print("patched", p)

def patch_crypto_reorder(root: pathlib.Path) -> None:
    p = root / "crypto_stream.go"
    text = p.read_text(encoding="utf-8")
    if "USQUE_QUIC_REORDER" in text:
        print("already patched", p)
        return
    old_struct = (
        "type initialCryptoStream struct {\n"
        "\tbaseCryptoStream\n"
        "\n"
        "\tscramble bool\n"
        "\tend      protocol.ByteCount\n"
        "\tcuts     [2]clientHelloCut\n"
        "}"
    )
    new_struct = (
        "type initialCryptoStream struct {\n"
        "\tbaseCryptoStream\n"
        "\n"
        "\tscramble     bool\n"
        "\treorder      bool\n"
        "\treorderPhase int\n"
        "\treorderOff   protocol.ByteCount\n"
        "\tend          protocol.ByteCount\n"
        "\tcuts         [2]clientHelloCut\n"
        "}"
    )
    if old_struct not in text:
        raise SystemExit("initialCryptoStream struct anchor missing")
    text = text.replace(old_struct, new_struct, 1)
    old_ctor = (
        "\tvar scramble bool\n"
        "\tif isClient {\n"
        "\t\tdisabled, err := strconv.ParseBool(os.Getenv(disableClientHelloScramblingEnv))\n"
        "\t\tscramble = err != nil || !disabled\n"
        "\t}\n"
        "\ts := &initialCryptoStream{\n"
        "\t\tbaseCryptoStream: baseCryptoStream{queue: *newFrameSorter()},\n"
        "\t\tscramble:         scramble,\n"
        "\t}\n"
    )
    new_ctor = (
        "\tvar scramble bool\n"
        "\treorder := isClient && os.Getenv(\"USQUE_QUIC_REORDER\") == \"1\"\n"
        "\tif isClient {\n"
        "\t\tdisabled, err := strconv.ParseBool(os.Getenv(disableClientHelloScramblingEnv))\n"
        "\t\tscramble = err != nil || !disabled\n"
        "\t}\n"
        "\tif reorder {\n"
        "\t\tscramble = true\n"
        "\t}\n"
        "\ts := &initialCryptoStream{\n"
        "\t\tbaseCryptoStream: baseCryptoStream{queue: *newFrameSorter()},\n"
        "\t\tscramble:         scramble,\n"
        "\t\treorder:          reorder,\n"
        "\t}\n"
    )
    if old_ctor not in text:
        raise SystemExit("initialCryptoStream ctor anchor missing")
    text = text.replace(old_ctor, new_ctor, 1)
    old_pop = (
        "func (s *initialCryptoStream) PopCryptoFrame(maxLen protocol.ByteCount) *wire.CryptoFrame {\n"
        "\tif !s.scramble {\n"
    )
    new_pop = (
        "func (s *initialCryptoStream) PopCryptoFrame(maxLen protocol.ByteCount) *wire.CryptoFrame {\n"
        "\tif s.reorder {\n"
        "\t\treturn s.popReorderedCrypto(maxLen)\n"
        "\t}\n"
        "\tif !s.scramble {\n"
    )
    if old_pop not in text:
        raise SystemExit("PopCryptoFrame anchor missing")
    text = text.replace(old_pop, new_pop, 1)
    text += (
        "\nfunc (s *initialCryptoStream) popReorderedCrypto(maxLen protocol.ByteCount) *wire.CryptoFrame {\n"
        "\tif s.cuts[0].start == protocol.InvalidByteCount || s.end == 0 {\n"
        "\t\treturn s.baseCryptoStream.PopCryptoFrame(maxLen)\n"
        "\t}\n"
        "\tcut := s.cuts[0].start\n"
        "\tif s.reorderPhase == 0 {\n"
        "\t\tif s.reorderOff == 0 {\n"
        "\t\t\ts.reorderOff = cut\n"
        "\t\t}\n"
        "\t\tif s.reorderOff < s.end {\n"
        "\t\t\tf := &wire.CryptoFrame{Offset: s.reorderOff}\n"
        "\t\t\tn := min(f.MaxDataLen(maxLen), s.end-s.reorderOff)\n"
        "\t\t\tif n <= 0 {\n"
        "\t\t\t\treturn nil\n"
        "\t\t\t}\n"
        "\t\t\tf.Data = s.writeBuf[s.reorderOff : s.reorderOff+n]\n"
        "\t\t\ts.reorderOff += n\n"
        "\t\t\treturn f\n"
        "\t\t}\n"
        "\t\ts.reorderPhase = 1\n"
        "\t\ts.reorderOff = 0\n"
        "\t}\n"
        "\tif s.reorderPhase == 1 && s.reorderOff < cut {\n"
        "\t\tf := &wire.CryptoFrame{Offset: s.reorderOff}\n"
        "\t\tn := min(f.MaxDataLen(maxLen), cut-s.reorderOff)\n"
        "\t\tif n <= 0 {\n"
        "\t\t\treturn nil\n"
        "\t\t}\n"
        "\t\tf.Data = s.writeBuf[s.reorderOff : s.reorderOff+n]\n"
        "\t\ts.reorderOff += n\n"
        "\t\treturn f\n"
        "\t}\n"
        "\ts.reorder = false\n"
        "\ts.scramble = false\n"
        "\ts.writeBuf = s.writeBuf[s.end:]\n"
        "\ts.writeOffset = s.end\n"
        "\ts.end = protocol.InvalidByteCount\n"
        "\treturn s.baseCryptoStream.PopCryptoFrame(maxLen)\n"
        "}\n"
    )
    p.write_text(text, encoding="utf-8", newline="\n")
    print("patched", p)

def patch_http3_max_payload(root: pathlib.Path) -> None:
    p = root / "connection.go"
    text = p.read_text(encoding="utf-8")
    if "usqueHTTP3MaxUDPPayload" in text:
        print("already patched", p)
        return
    old_imp = '\t"net"\n'
    if old_imp not in text:
        raise SystemExit("connection.go import anchor missing")
    text = text.replace(
        old_imp,
        old_imp + '\t"os"\n\t"strconv"\n',
        1,
    )
    # Client constructor only. The server assignment uses one more space
    # before protocol.MaxPacketBufferSize and must stay at 1452.
    old_client = (
        "\t\tMaxUDPPayloadSize:              protocol.MaxPacketBufferSize,\n"
        "\t\tAckDelayExponent:               protocol.AckDelayExponent,\n"
    )
    new_client = (
        "\t\tMaxUDPPayloadSize:              usqueHTTP3MaxUDPPayload(protocol.MaxPacketBufferSize),\n"
        "\t\tAckDelayExponent:               protocol.AckDelayExponent,\n"
    )
    if old_client not in text:
        raise SystemExit("client max_udp_payload_size anchor missing")
    text = text.replace(old_client, new_client, 1)
    old_dgram = (
        "\tif s.config.EnableDatagrams {\n"
        "\t\tparams.MaxDatagramFrameSize = wire.MaxDatagramSize\n"
        "\t} else {\n"
        "\t\tparams.MaxDatagramFrameSize = protocol.InvalidByteCount\n"
        "\t}\n"
        "\tif s.qlogger != nil {\n"
        "\t\ts.qlogTransportParameters(params, protocol.PerspectiveClient, false)\n"
        "\t}\n"
    )
    new_dgram = (
        "\tif s.config.EnableDatagrams {\n"
        "\t\tparams.MaxDatagramFrameSize = usqueHTTP3MaxDatagram(wire.MaxDatagramSize)\n"
        "\t} else {\n"
        "\t\tparams.MaxDatagramFrameSize = protocol.InvalidByteCount\n"
        "\t}\n"
        "\tif s.qlogger != nil {\n"
        "\t\ts.qlogTransportParameters(params, protocol.PerspectiveClient, false)\n"
        "\t}\n"
    )
    if old_dgram not in text:
        raise SystemExit("client datagram anchor missing")
    text = text.replace(old_dgram, new_dgram, 1)
    text += (
        "\n// usqueHTTP3MaxUDPPayload limits only the HTTP/3 client advertisement.\n"
        "// USQUE_H3_MAX_UDP_PAYLOAD is set by usque around the MASQUE HTTP/3 dial.\n"
        "// An empty or invalid value keeps quic-go's default.\n"
        "func usqueHTTP3MaxUDPPayload(fallback protocol.ByteCount) protocol.ByteCount {\n"
        "\traw := os.Getenv(\"USQUE_H3_MAX_UDP_PAYLOAD\")\n"
        "\tif raw == \"\" {\n"
        "\t\treturn fallback\n"
        "\t}\n"
        "\tn, err := strconv.Atoi(raw)\n"
        "\tif err != nil || n < 1200 || protocol.ByteCount(n) > protocol.MaxPacketBufferSize {\n"
        "\t\treturn fallback\n"
        "\t}\n"
        "\treturn protocol.ByteCount(n)\n"
        "}\n"
        "\n// usqueHTTP3MaxDatagram keeps a MASQUE IP packet of MTU 1000 inside the\n"
        "// 1200-byte UDP payload. Unset, the default 16383 datagram limit remains.\n"
        "func usqueHTTP3MaxDatagram(fallback protocol.ByteCount) protocol.ByteCount {\n"
        "\tif os.Getenv(\"USQUE_H3_MAX_UDP_PAYLOAD\") == \"\" {\n"
        "\t\treturn fallback\n"
        "\t}\n"
        "\tconst max protocol.ByteCount = 1100\n"
        "\tif fallback > max {\n"
        "\t\treturn max\n"
        "\t}\n"
        "\treturn fallback\n"
        "}\n"
    )
    p.write_text(text, encoding="utf-8", newline="\n")
    print("patched", p)

def main() -> None:
    root = pathlib.Path(sys.argv[1])
    patch_initial_split(root)
    patch_crypto_reorder(root)
    patch_http3_max_payload(root)

if __name__ == "__main__":
    main()
