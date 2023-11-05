package cborutils

import "github.com/shogo82148/go-cbor"

// IntegerFromInt64 converts int64 to cbor.Integer.
func IntegerFromInt64(i int64) cbor.Integer {
	var sign bool
	if i < 0 {
		sign = true
		i = ^i
	}
	return cbor.Integer{
		Sign:  sign,
		Value: uint64(i),
	}
}
