package http3

import (
	"errors"
	"io"

	"github.com/quic-go/qpack"
)

// decodeFull adapts the qpack v0.6 iterator API to the slice API used by this
// Psiphon quic-go fork. The unified PersianRay module must use qpack v0.6
// because Xray's QUIC implementation requires it.
func decodeFull(decoder *qpack.Decoder, block []byte) ([]qpack.HeaderField, error) {
	next := decoder.Decode(block)
	var fields []qpack.HeaderField
	for {
		field, err := next()
		if errors.Is(err, io.EOF) {
			return fields, nil
		}
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
}
