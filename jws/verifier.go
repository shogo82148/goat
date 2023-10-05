package jws

import (
	"errors"

	"github.com/shogo82148/goat/sig"
)

var errVerifyFailed = errors.New("jws: failed to verify the message")

// KeyFinder is a wrapper for the FindKey method.
type KeyFinder interface {
	// FindKey finds a signing key for the JWS message.
	FindKey(protected, unprotected *Header) (key sig.SigningKey, err error)
}

// FindKeyFunc is an adapter to allow the use of ordinary functions as KeyFinder.
type FindKeyFunc func(protected, unprotected *Header) (key sig.SigningKey, err error)

func (f FindKeyFunc) FindKey(protected, unprotected *Header) (key sig.SigningKey, err error) {
	return f(protected, unprotected)
}

// Verifier verifies the JWS message.
type Verifier struct {
	KeyFinder KeyFinder
}

// Verify verifies the JWS message.
func (v *Verifier) Verify(msg *Message) (protected *Header, payload []byte, err error) {
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
		key, err := v.KeyFinder.FindKey(sig.protected, sig.header)
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
