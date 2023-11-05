package cborutils

import "github.com/shogo82148/go-cbor"

type Decoder struct {
	pkg string
	raw map[any]any
}

func NewDecoder(pkg string, raw map[any]any) *Decoder {
	return &Decoder{
		pkg: pkg,
		raw: raw,
	}
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
