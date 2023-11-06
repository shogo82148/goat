package cborutils

import "github.com/shogo82148/go-cbor"

type Decoder struct {
	pkg string
	raw map[any]any
	err error
}

func NewDecoder(pkg string, raw map[any]any) *Decoder {
	return &Decoder{
		pkg: pkg,
		raw: raw,
	}
}

func (d *Decoder) SaveError(err error) {
	if d.err == nil {
		d.err = err
	}
}

func (d *Decoder) Err() error {
	return d.err
}

// Has returns true if the label exists.
func (d *Decoder) Has(label int64) bool {
	i := IntegerFromInt64(label)
	_, ok := d.raw[i]
	return ok
}

// GetInteger gets an integer parameter.
func (d *Decoder) GetInteger(label int64) (cbor.Integer, bool) {
	v, ok := d.raw[IntegerFromInt64(label)]
	if !ok {
		return cbor.Integer{}, false
	}

	i, ok := v.(cbor.Integer)
	return i, ok
}

// GetString gets a string parameter.
func (d *Decoder) GetString(label int64) (string, bool) {
	v, ok := d.raw[IntegerFromInt64(label)]
	if !ok {
		return "", false
	}

	s, ok := v.(string)
	return s, ok
}
