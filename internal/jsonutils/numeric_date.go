package jsonutils

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"time"
)

// NumericDate represents a JSON numeric date value defined in [RFC 7519] Section 2.
//
// [RFC 7519]: https://tools.ietf.org/html/rfc7519
type NumericDate struct {
	time.Time
}

// the maximum time epoch that Go can marshal to JSON.
const maxEpoch = 253402300799

func (date NumericDate) MarshalJSON() (b []byte, err error) {
	// the maximum time.Time that Go can marshal to JSON.
	const maxTime = "+253402300799.999999999"

	buf := make([]byte, 0, len(maxTime))
	sec := date.Unix()
	nsec := date.Nanosecond()
	if sec < 0 && nsec != 0 {
		// handle the sign
		sec++
		nsec = 1_000_000_000 - nsec
		if sec < 0 {
			sec = -sec
		}
		buf = append(buf, '-')
	}
	if sec > maxEpoch || sec < -maxEpoch {
		return nil, fmt.Errorf("unix time epoch overflow: %d", sec)
	}
	buf = strconv.AppendInt(buf, sec, 10)

	// non-integer values can be represented.
	if nsec != 0 {
		buf = append(buf, '.')
		digits := 100_000_000
		for nsec != 0 {
			d := nsec / digits
			buf = append(buf, byte('0'+d))
			nsec = nsec % digits
			digits /= 10
		}
	}
	return buf, nil
}

var v1_000_000_000 = new(big.Float).SetInt64(1_000_000_000)

func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	z := new(big.Float).SetPrec(128)
	if err := z.UnmarshalText(b); err != nil {
		return err
	}
	sec, acc := z.Int64()
	if acc == big.Exact {
		// z is an integer, we don't need to parse nsec.
		if sec > maxEpoch || sec < -maxEpoch {
			return fmt.Errorf("unix time epoch overflow: %d", sec)
		}
		date.Time = time.Unix(sec, 0).UTC()
		return nil
	}

	// non-integer values can be represented.
	z = z.Sub(z, new(big.Float).SetInt64(sec))
	z = z.Mul(z, v1_000_000_000)
	nsec, _ := z.Float64()
	ns := int64(math.Trunc(nsec))
	if ns >= 1_000_000_000 {
		ns -= 1_000_000_000
		sec++
	}
	if ns <= -1_000_000_000 {
		ns += 1_000_000_000
		sec--
	}
	if sec > maxEpoch || sec < -maxEpoch {
		return fmt.Errorf("unix time epoch overflow: %d", sec)
	}
	date.Time = time.Unix(sec, ns).UTC()
	return nil
}
