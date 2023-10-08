package jws

import (
	"context"
	"errors"

	"github.com/shogo82148/goat/jwa"
)

var errVerifyFailed = errors.New("jws: failed to verify the message")

// AlgorithmVerfier verifies the algorithm used for signing.
type AlgorithmVerfier interface {
	VerifyAlgorithm(ctx context.Context, alg jwa.SignatureAlgorithm) error
}

type AllowedAlgorithms []jwa.SignatureAlgorithm

func (a AllowedAlgorithms) VerifyAlgorithm(ctx context.Context, alg jwa.SignatureAlgorithm) error {
	for _, allowed := range a {
		if alg == allowed {
			return nil
		}
	}
	return errors.New("jws: signing algorithm is not allowed")
}

// UnsecureAnyAlgorithm is an AlgorithmVerfier that accepts any algorithm.
var UnsecureAnyAlgorithm = unsecureAnyAlgorithmVerifier{}

type unsecureAnyAlgorithmVerifier struct{}

func (unsecureAnyAlgorithmVerifier) VerifyAlgorithm(ctx context.Context, alg jwa.SignatureAlgorithm) error {
	return nil
}

// Verifier verifies the JWS message.
type Verifier struct {
	_NamedFieldsRequired struct{}

	AlgorithmVerfier AlgorithmVerfier
	KeyFinder        KeyFinder
}

// Verify verifies the JWS message.
func (v *Verifier) Verify(ctx context.Context, msg *Message) (protected *Header, payload []byte, err error) {
	_ = v._NamedFieldsRequired
	if v.AlgorithmVerfier == nil || v.KeyFinder == nil {
		return nil, nil, errors.New("jws: verifier is not configured")
	}

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
		if err := v.AlgorithmVerfier.VerifyAlgorithm(ctx, sig.protected.alg); err != nil {
			continue
		}
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
