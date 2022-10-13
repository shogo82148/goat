package jwt

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
)

// EncodeCustom encodes custom claims from v.
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
