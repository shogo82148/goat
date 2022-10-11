package jsonutils

import (
	"encoding/json"
	"math/big"
	"time"
)

type Encoder struct {
	raw map[string]any

	// pre-allocates base64 buffers.
	src []byte
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
	if cap(e.src) >= n {
		return
	}
	if n < 64 {
		n = 64
	}
	e.src = make([]byte, n)
	e.dst = make([]byte, b64.EncodedLen(n))
}

func (e *Encoder) Set(name string, v any) {
	e.raw[name] = v
}

func (e *Encoder) SetBytes(name string, data []byte) {
	e.raw[name] = e.Encode(data)
}

func (e *Encoder) SetBigInt(name string, i *big.Int) {
	e.SetFixedBigInt(name, i, (i.BitLen()+7)/8)
}

func (e *Encoder) SetFixedBigInt(name string, i *big.Int, size int) {
	e.grow(size)
	src := i.FillBytes(e.src[:size])
	e.raw[name] = e.Encode(src)
}

func (e *Encoder) SetTime(name string, t time.Time) {
	data, err := NumericDate{Time: t}.MarshalJSON()
	if err != nil {
		e.SaveError(err)
		return
	}
	e.raw[name] = json.RawMessage(data)
}

func (e *Encoder) Encode(s []byte) string {
	e.grow(len(s))
	dst := e.dst[:b64.EncodedLen(len(s))]
	b64.Encode(dst, s)
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
