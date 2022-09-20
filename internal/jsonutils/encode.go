package jsonutils

import (
	"encoding/base64"
	"math/big"
)

type Encoder struct {
	raw map[string]any

	// pre-allocates base64 decoding buffers.
	dst []byte

	err error
}

func NewEncoder(raw map[string]any) *Encoder {
	if raw == nil {
		raw = make(map[string]any)
	}
	return &Encoder{
		raw: raw,
	}
}

func (e *Encoder) Data() map[string]any {
	return e.raw
}

func (e *Encoder) grow(n int) {
	m := base64.RawURLEncoding.EncodedLen(n)
	if cap(e.dst) >= m {
		return
	}
	if m < 64 {
		m = 64
	}
	e.dst = make([]byte, m)
}

func (e *Encoder) Set(name string, v any) {
	e.raw[name] = v
}

func (e *Encoder) SetBytes(name string, data []byte) {
	e.raw[name] = e.Encode(data)
}

func (e *Encoder) SetBigInt(name string, i *big.Int) {
	e.raw[name] = e.Encode(i.Bytes())
}

func (e *Encoder) Encode(s []byte) string {
	e.grow(len(s))
	dst := e.dst[:base64.RawURLEncoding.EncodedLen(len(s))]
	base64.RawURLEncoding.Encode(dst, s)
	return string(dst)
}

// SaveError asserts the operation must not fail.
// If err is nil, SaveError does nothing.
// Otherwise, SaveError records the first error.
func (e *Encoder) SaveError(err error) {
	if err != nil && e.err == nil {
		e.err = err
	}
}

func (e *Encoder) Err() error {
	return e.err
}
