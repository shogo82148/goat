package jwk

import (
	"encoding/base64"
	"fmt"
)

type decodeContext struct {
	raw map[string]any

	// pre-allocates base64 decoding buffers.
	src []byte
	dst []byte

	// first error
	err error
}

func maxStringLen(raw any) int {
	size := 0
	switch v := raw.(type) {
	case []any:
		for _, u := range v {
			l := maxStringLen(u)
			if l > size {
				size = l
			}
		}
	case map[string]any:
		for _, u := range v {
			l := maxStringLen(u)
			if l > size {
				size = l
			}
		}
	case string:
		size = len(v)
	}
	return size
}

func newDecodeContext(raw map[string]any) *decodeContext {
	n := maxStringLen(raw)
	src := make([]byte, n)
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(n))
	return &decodeContext{
		raw: raw,
		src: src,
		dst: dst,
	}
}

func get[T any](ctx *decodeContext, name string) (T, bool) {
	v, ok := ctx.raw[name]
	if !ok {
		var zero T
		return zero, false
	}
	u, ok := v.(T)
	if !ok && ctx.err == nil {
		ctx.err = fmt.Errorf("jwk: unexpected type for the parameter %s: %T", name, v)
	}
	return u, ok
}

func must[T any](ctx *decodeContext, name string) T {
	v, ok := get[T](ctx, name)
	if !ok && ctx.err == nil {
		ctx.err = fmt.Errorf("jwk: required parameter %s is missing", name)
	}
	return v
}

func (ctx *decodeContext) getBytes(name string) ([]byte, bool) {
	s, ok := get[string](ctx, name)
	if !ok {
		return nil, false
	}
	data := ctx.decode(s, name)
	return data, true
}

func (ctx *decodeContext) mustBytes(name string) []byte {
	s, ok := get[string](ctx, name)
	if !ok {
		ctx.error(fmt.Errorf("jwk: required parameter %s is missing", name))
		return nil
	}
	data := ctx.decode(s, name)
	return data
}

func (ctx *decodeContext) has(name string) bool {
	_, ok := ctx.raw[name]
	return ok
}

// decode decodes s as base64 raw url encoding.
// the returned slice is valid until next call.
func (ctx *decodeContext) decode(s string, name string) []byte {
	src := ctx.src[:len(s)]
	copy(src, s)
	dst := ctx.dst[:cap(ctx.dst)]
	n, err := base64.RawURLEncoding.Decode(dst, src)
	if err != nil && ctx.err == nil {
		ctx.err = &base64DecodeError{
			name: name,
			err:  err,
		}
	}
	return dst[:n]
}

// decode decodes s as base64 standard encoding.
// the returned slice is valid until next call.
func (ctx *decodeContext) decodeStd(s string, name string) []byte {
	src := ctx.src[:len(s)]
	copy(src, s)
	n, err := base64.StdEncoding.Decode(ctx.dst, src)
	if err != nil {
		ctx.error(&base64DecodeError{
			name: name,
			err:  err,
		})
	}
	return ctx.dst[:n]
}

func (ctx *decodeContext) error(err error) {
	if err != nil && ctx.err == nil {
		ctx.err = err
	}
}

type base64DecodeError struct {
	name string
	err  error
}

// Error implements the error interface.
func (err *base64DecodeError) Error() string {
	return fmt.Sprintf("jwk: failed to parse the parameter %s: %v", err.name, err.err)
}

func (err *base64DecodeError) Unwrap() error {
	return err.err
}
