package jws

import (
	"context"
	"errors"
)

var errVerifyFailed = errors.New("jws: failed to verify the message")

// Verifier verifies the JWS message.
type Verifier struct {
	KeyFinder KeyFinder
}

// Verify verifies the JWS message.
func (v *Verifier) Verify(ctx context.Context, msg *Message) (protected *Header, payload []byte, err error) {
	// pre-allocate buffer
	size := 0
	for _, sig := range msg.Signatures {
		if len(sig.raw) > size {
			size = len(sig.raw)
		}
	}
	size += len(msg.payload) + 1 // +1 for '.'
	buf := make([]byte, size)

	for _, sig := range msg.Signatures {
		key, err := v.KeyFinder.FindKey(ctx, sig.protected, sig.header)
		if err != nil {
			continue
		}
		buf = buf[:0]
		buf = append(buf, sig.raw...)
		buf = append(buf, '.')
		buf = append(buf, msg.payload...)
		err = key.Verify(buf, sig.signature)
		if err == nil {
			var ret []byte
			if sig.protected.b64 {
				ret, err = b64Decode(msg.payload)
				if err != nil {
					return nil, nil, errVerifyFailed
				}
			} else {
				ret = msg.payload
			}
			return sig.protected, ret, nil
		}
	}
	return nil, nil, errVerifyFailed
}
