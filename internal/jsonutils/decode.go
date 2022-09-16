// jsonutils package is utilities for handling JSON.
package jsonutils

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"reflect"
)

type Decoder struct {
	pkg string
	raw map[string]any

	// pre-allocates base64 decoding buffers.
	src []byte
	dst []byte

	// first error
	err error
}

func NewDecoder(pkg string, raw map[string]any) *Decoder {
	return &Decoder{
		pkg: pkg,
		raw: raw,
	}
}

func (d *Decoder) grow(n int) {
	if cap(d.src) >= n {
		return
	}
	if n < 64 {
		n = 64
	}
	d.src = make([]byte, n)
	d.dst = make([]byte, base64.RawURLEncoding.DecodedLen(n))
}

// Decode decodes s as base64 raw url encoding.
// the returned slice is valid until next call.
func (d *Decoder) Decode(s string, name string) []byte {
	d.grow(len(s))
	src := d.src[:len(s)]
	dst := d.dst[:cap(d.dst)]
	copy(src, s)
	n, err := base64.RawURLEncoding.Decode(dst, src)
	if err != nil {
		if d.err == nil {
			d.err = &base64DecodeError{
				pkg:  d.pkg,
				name: name,
				err:  err,
			}
		}
		return nil
	}
	return dst[:n]
}

// DecodeStd decodes s as base64 standard encoding.
// the returned slice is valid until next call.
func (d *Decoder) DecodeStd(s string, name string) []byte {
	d.grow(len(s))
	src := d.src[:len(s)]
	dst := d.dst[:cap(d.dst)]
	copy(src, s)
	n, err := base64.StdEncoding.Decode(dst, src)
	if err != nil {
		if d.err == nil {
			d.err = &base64DecodeError{
				pkg:  d.pkg,
				name: name,
				err:  err,
			}
		}
		return nil
	}
	return dst[:n]
}

func (d *Decoder) Has(name string) bool {
	_, ok := d.raw[name]
	return ok
}

// GetString gets a string parameter.
func (d *Decoder) GetString(name string) (string, bool) {
	v, ok := d.raw[name]
	if !ok {
		return "", false
	}
	u, ok := v.(string)
	if !ok {
		if d.err == nil {
			d.err = &typeError{
				pkg:  d.pkg,
				name: name,
				want: "string",
				got:  reflect.TypeOf(v),
			}
		}
		return "", false
	}
	return u, true
}

// MustString gets a string parameter.
func (d *Decoder) MustString(name string) string {
	v, ok := d.raw[name]
	if !ok {
		if d.err == nil {
			d.err = &missingError{
				pkg:  d.pkg,
				name: name,
			}
		}
		return ""
	}
	u, ok := v.(string)
	if !ok {
		if d.err == nil {
			d.err = &typeError{
				pkg:  d.pkg,
				name: name,
				want: "string",
				got:  reflect.TypeOf(v),
			}
		}
		return ""
	}
	return u
}

func (d *Decoder) GetArray(name string) ([]any, bool) {
	v, ok := d.raw[name]
	if !ok {
		return nil, false
	}
	u, ok := v.([]any)
	if !ok {
		if d.err == nil {
			d.err = &typeError{
				pkg:  d.pkg,
				name: name,
				want: "[]any",
				got:  reflect.TypeOf(v),
			}
		}
		return nil, false
	}
	return u, true

}

func (d *Decoder) MustArray(name string) []any {
	v, ok := d.raw[name]
	if !ok {
		if d.err == nil {
			d.err = &missingError{
				pkg:  d.pkg,
				name: name,
			}
		}
		return nil
	}
	u, ok := v.([]any)
	if !ok {
		if d.err == nil {
			d.err = &typeError{
				pkg:  d.pkg,
				name: name,
				want: "string",
				got:  reflect.TypeOf(v),
			}
		}
		return nil
	}
	return u
}

func (d *Decoder) GetBytes(name string) ([]byte, bool) {
	s, ok := d.GetString(name)
	if !ok {
		return nil, false
	}
	data := d.Decode(s, name)
	if data == nil {
		return nil, false
	}
	return data, true
}

func (d *Decoder) MustBytes(name string) []byte {
	s := d.MustString(name)
	if s == "" {
		return nil
	}
	return d.Decode(s, name)
}

func (d *Decoder) GetBigInt(name string) (*big.Int, bool) {
	data, ok := d.GetBytes(name)
	if !ok {
		return nil, false
	}
	return new(big.Int).SetBytes(data), true
}

func (d *Decoder) MustBigInt(name string) *big.Int {
	data := d.MustBytes(name)
	if data == nil {
		return nil
	}
	return new(big.Int).SetBytes(data)
}

// Must asserts the operation must not fail.
// If err is nil, Must does nothing.
// Otherwise, Must records the first error.
func (d *Decoder) Must(err error) {
	if err != nil && d.err == nil {
		d.err = err
	}
}

// Err returns the first error during decoding.
func (d *Decoder) Err() error {
	return d.err
}

type base64DecodeError struct {
	pkg  string
	name string
	err  error
}

func (err *base64DecodeError) Error() string {
	return fmt.Sprintf("%s: failed to parse the parameter %s: %v", err.pkg, err.name, err.err)
}

func (err *base64DecodeError) Unwrap() error {
	return err.err
}

type typeError struct {
	pkg  string
	name string
	want string
	got  reflect.Type
}

func (err *typeError) Error() string {
	return fmt.Sprintf("%s: want %s for the parameter %s but got %s", err.pkg, err.want, err.name, err.got.String())
}

type missingError struct {
	pkg  string
	name string
}

func (err *missingError) Error() string {
	return fmt.Sprintf("%s: required parameter %s is missing", err.pkg, err.name)
}
