package jwt

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/shogo82148/goat/internal/jsonutils"
)

// EncodeCustom encodes custom claims from v.
//
// EncodeCustom works like [encoding/json.Marshal], with a few differences.
// Due to the different value conversion rules,
// the "jwt" key is used for structure field tags instead of the "json" key.
//
// The following conversions are made to match the general encoding of JWT claims:
//
//   - []byte is converted to base64 raw-url encoded string
//   - big.Int is converted to big-endian base64 raw-url encoded string
//   - *time.Time is converted to number in seconds from unix time epoch
//
// The tag must always be specified to avoid accidentally exposing the field.
// Claim names are case sensitive.
func (c *Claims) EncodeCustom(v any) error {
	// sanity check of type
	rv := reflect.ValueOf(v)

	// encode
	ret, err := encode(rv)
	if err != nil {
		return err
	}

	// set them as claims
	raw, ok := ret.(map[string]any)
	if !ok {
		return fmt.Errorf("jwt: invalid type: %s", rv.Type().String())
	}
	if c.Raw == nil {
		c.Raw = raw
	} else {
		for k, v := range raw {
			c.Raw[k] = v
		}
	}

	return nil
}

func encode(in reflect.Value) (any, error) {
	in = indirect(in)
	typ := in.Type()
	switch typ.Kind() {
	case reflect.String:
		return in.String(), nil
	case reflect.Bool:
		return in.Bool(), nil
	case reflect.Float32, reflect.Float64:
		str := strconv.FormatFloat(in.Float(), 'f', -1, typ.Bits())
		return json.Number(str), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		str := strconv.FormatInt(in.Int(), 10)
		return json.Number(str), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		str := strconv.FormatUint(in.Uint(), 10)
		return json.Number(str), nil
	case reflect.Struct:
		switch typ {
		case timeType:
			t := jsonutils.NumericDate{
				Time: in.Interface().(time.Time),
			}
			data, err := t.MarshalJSON()
			if err != nil {
				return nil, err
			}
			return json.Number(data), nil
		case urlType:
			u := in.Interface().(url.URL)
			return u.String(), nil
		case bigIntType:
			i := in.Interface().(big.Int)
			data := b64.EncodeToString(i.Bytes())
			return data, nil
		}
		fields := cachedTypeFields(typ)
		ret := make(map[string]any, len(fields))
		for _, f := range fields {
			subv := in
			for _, i := range f.index {
				if subv.Kind() == reflect.Ptr {
					if subv.IsNil() {
						if !subv.CanSet() {
							return nil, fmt.Errorf("jwt: cannot set pointer to unexported struct: %v", subv.Type().Elem())
						}
						subv.Set(reflect.New(subv.Type().Elem()))
					}
					subv = subv.Elem()
				}
				subv = subv.Field(i)
			}
			v, err := encode(subv)
			if err != nil {
				return nil, err
			}
			ret[f.name] = v
		}
		return ret, nil
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			bytes := in.Interface().([]byte)
			return b64.EncodeToString(bytes), nil
		}
		ret := make([]any, typ.Len())
		for i := range ret {
			v, err := encode(in.Index(i))
			if err != nil {
				return nil, err
			}
			ret[i] = v
		}
		return ret, nil
	default:
		return nil, fmt.Errorf("jwt: unknown type %s", typ.String())
	}
}
