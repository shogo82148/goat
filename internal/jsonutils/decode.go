// jsonutils package is utilities for handling JSON.
package jsonutils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"reflect"
	"strconv"
	"time"
)

var b64 = base64.RawURLEncoding

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
	d.dst = make([]byte, b64.DecodedLen(n))
}

// Decode decodes s as base64 raw url encoding.
// the returned slice is valid until next call.
func (d *Decoder) Decode(s string, name string) []byte {
	d.grow(len(s))
	return d.decode(d.dst, s, name)
}

func (d *Decoder) decode(dst []byte, s, name string) []byte {
	d.grow(len(s))
	src := d.src[:len(s)]
	copy(src, s)
	n, err := b64.Decode(dst, src)
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
				want: "[]any",
				got:  reflect.TypeOf(v),
			}
		}
		return nil
	}
	return u
}

func (d *Decoder) GetObject(name string) (map[string]any, bool) {
	v, ok := d.raw[name]
	if !ok {
		return nil, false
	}
	u, ok := v.(map[string]any)
	if !ok {
		if d.err == nil {
			d.err = &typeError{
				pkg:  d.pkg,
				name: name,
				want: "map[string]any",
				got:  reflect.TypeOf(v),
			}
		}
		return nil, false
	}
	return u, true
}

func (d *Decoder) GetStringArray(name string) ([]string, bool) {
	array, ok := d.GetArray(name)
	if !ok {
		return nil, false
	}
	ret := make([]string, 0, len(array))
	for i, v := range array {
		s, ok := v.(string)
		if !ok {
			if d.err == nil {
				d.err = &typeError{
					pkg:  d.pkg,
					name: name + "[" + strconv.Itoa(i) + "]",
					want: "string",
					got:  reflect.TypeOf(v),
				}
			}
			return nil, false
		}
		ret = append(ret, s)
	}
	return ret, true
}

func (d *Decoder) GetBytes(name string) ([]byte, bool) {
	s, ok := d.GetString(name)
	if !ok {
		return nil, false
	}
	buf := make([]byte, b64.DecodedLen(len(s)))
	return d.decode(buf, s, name), true
}

func (d *Decoder) MustBytes(name string) []byte {
	s, ok := d.GetString(name)
	if !ok {
		if d.err == nil {
			d.err = &missingError{
				pkg:  d.pkg,
				name: name,
			}
		}
		return nil
	}
	buf := make([]byte, b64.DecodedLen(len(s)))
	return d.decode(buf, s, name)
}

func (d *Decoder) GetBigInt(name string) (*big.Int, bool) {
	s, ok := d.GetString(name)
	if !ok {
		return nil, false
	}
	data := d.Decode(s, name)
	if d.err != nil {
		return nil, false
	}
	return new(big.Int).SetBytes(data), true
}

func (d *Decoder) MustBigInt(name string) *big.Int {
	n, ok := d.GetBigInt(name)
	if !ok {
		if d.err == nil {
			d.err = &missingError{
				pkg:  d.pkg,
				name: name,
			}
		}
		return nil
	}
	return n
}

func (d *Decoder) GetURL(name string) (*url.URL, bool) {
	s, ok := d.GetString(name)
	if !ok {
		return nil, false
	}
	u, err := url.Parse(s)
	if err != nil {
		if d.err == nil {
			d.err = fmt.Errorf("%s: failed to parse the parameter %s as url: %v", d.pkg, name, err)
		}
		return nil, false
	}
	return u, true
}

func (d *Decoder) GetTime(name string) (time.Time, bool) {
	v, ok := d.raw[name]
	if !ok {
		return time.Time{}, false
	}
	switch v := v.(type) {
	case json.Number:
		var t NumericDate
		if err := t.UnmarshalJSON([]byte(v)); err != nil {
			if d.err == nil {
				d.err = fmt.Errorf("%s: failed to parse parameter %s", d.pkg, name)
			}
			return time.Time{}, false
		}
		return t.Time, true
	case float64:
		i, f := math.Modf(v)
		t := time.Unix(int64(i), int64(f*1e9))
		return t, true
	}
	if d.err == nil {
		d.err = &typeError{
			pkg:  d.pkg,
			name: name,
			want: "number",
			got:  reflect.TypeOf(v),
		}
	}
	return time.Time{}, false
}

func (d *Decoder) GetInt64(name string) (int64, bool) {
	v, ok := d.raw[name]
	if !ok {
		return 0, false
	}
	switch v := v.(type) {
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			if d.err == nil {
				d.err = fmt.Errorf("%s: failed to parse integer parameter %s: %w", d.pkg, name, err)
			}
			return 0, false
		}
		return i, true
	case float64:
		i, f := math.Modf(v)
		if f != 0 {
			if d.err == nil {
				d.err = fmt.Errorf("%s: failed to parse integer parameter %s", d.pkg, name)
			}
			return 0, false
		}
		if i > math.MaxInt64 || i < math.MinInt64 {
			if d.err == nil {
				d.err = fmt.Errorf("%s: integer parameter %s is overflow", d.pkg, name)
			}
			return 0, false
		}
		return int64(i), true
	}
	if d.err == nil {
		d.err = &typeError{
			pkg:  d.pkg,
			name: name,
			want: "number",
			got:  reflect.TypeOf(v),
		}
	}
	return 0, false
}

func (d *Decoder) MustInt64(name string) int64 {
	n, ok := d.GetInt64(name)
	if !ok {
		if d.err == nil {
			d.err = &missingError{
				pkg:  d.pkg,
				name: name,
			}
		}
		return 0
	}
	return n
}

// SaveError asserts the operation must not fail.
// If err is nil, SaveError does nothing.
// Otherwise, SaveError records the first error.
func (d *Decoder) SaveError(err error) {
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
	return fmt.Sprintf("%s: failed to parse the parameter %s as base64url: %v", err.pkg, err.name, err.err)
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
