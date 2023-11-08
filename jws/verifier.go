package jws

import (
	"context"
	"errors"

	"github.com/shogo82148/goat/jwa"
)

var errVerifyFailed = errors.New("jws: failed to verify the message")

// AlgorithmVerifier verifies the algorithm used for signing.
type AlgorithmVerifier interface {
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

// UnsecureAnyAlgorithm is an AlgorithmVerifier that accepts any algorithm.
var UnsecureAnyAlgorithm = unsecureAnyAlgorithmVerifier{}

type unsecureAnyAlgorithmVerifier struct{}

func (unsecureAnyAlgorithmVerifier) VerifyAlgorithm(ctx context.Context, alg jwa.SignatureAlgorithm) error {
	return nil
}

// Verifier verifies the JWS message.
type Verifier struct {
	_NamedFieldsRequired struct{}

	AlgorithmVerifier AlgorithmVerifier
	KeyFinder         KeyFinder
}

// Verify verifies the JWS message.
func (v *Verifier) Verify(ctx context.Context, msg *Message) (protected, unprotected *Header, payload []byte, err error) {
	if v.AlgorithmVerifier == nil || v.KeyFinder == nil {
		return nil, nil, nil, errors.New("jws: verifier is not configured")
	}

	var rawContent, b64Content []byte
	if msg.b64 {
		rawContent, err = b64Decode(msg.payload)
		if err != nil {
			return nil, nil, nil, errVerifyFailed
		}
		b64Content = msg.payload
	} else {
		rawContent = msg.payload
		b64Content = b64Encode(rawContent)
	}
	return v.verify(ctx, msg, rawContent, b64Content)
}

func (v *Verifier) VerifyContent(ctx context.Context, msg *Message, content []byte) (protected, unprotected *Header, payload []byte, err error) {
	if v.AlgorithmVerifier == nil || v.KeyFinder == nil {
		return nil, nil, nil, errors.New("jws: verifier is not configured")
	}

	b64Content := b64Encode(content)
	return v.verify(ctx, msg, content, b64Content)
}

func (v *Verifier) verify(ctx context.Context, msg *Message, rawContent, b64Content []byte) (protected, unprotected *Header, payload []byte, err error) {
	_ = v._NamedFieldsRequired
	// pre-allocate buffer
	size := 0
	for _, sig := range msg.Signatures {
		if len(sig.raw) > size {
			size = len(sig.raw)
		}
	}
	size += len(b64Content) + 1 // +1 for '.'
	buf := make([]byte, size)

	for _, sig := range msg.Signatures {
		if err := v.AlgorithmVerifier.VerifyAlgorithm(ctx, sig.protected.alg); err != nil {
			continue
		}
		key, err := v.KeyFinder.FindKey(ctx, sig.protected, sig.header)
		if err != nil {
			continue
		}
		buf = buf[:0]
		buf = append(buf, sig.raw...)
		buf = append(buf, '.')
		buf = append(buf, b64Content...)
		err = key.Verify(buf, sig.signature)
		if err == nil {
			return sig.protected, sig.header, rawContent, nil
		}
	}
	return nil, nil, nil, errVerifyFailed
}
