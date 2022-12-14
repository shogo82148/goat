package jwt

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/shogo82148/goat/internal/jsonutils"
)

var timeType = reflect.TypeOf(time.Time{})
var urlType = reflect.TypeOf(url.URL{})
var bigIntType = reflect.TypeOf(big.Int{})

// DecodeCustom decodes custom claims into v.
// v must be a pointer.
func (c *Claims) DecodeCustom(v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("jwt: invalid decode type: %s", reflect.TypeOf(v))
	}
	return decode(c.Raw, rv)
}

func indirect(v reflect.Value) reflect.Value {
	for {
		if v.Kind() != reflect.Ptr {
			break
		}
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
	}
	return v
}

func decode(in any, out reflect.Value) error {
	out = indirect(out)
	switch in := in.(type) {
	case string:
		switch out.Kind() {
		case reflect.String:
			out.SetString(in)
		case reflect.Slice:
			switch out.Type().Elem().Kind() {
			case reflect.Uint8:
				b, err := b64.DecodeString(in)
				if err != nil {
					return fmt.Errorf("jwt: failed to decode base64url string: %w", err)
				}
				out.SetBytes(b)
			case reflect.String:
				if out.Cap() == 0 {
					out.Set(reflect.MakeSlice(out.Type(), 1, 1))
				}
				out.SetLen(1)
				out.Index(0).SetString(in)
			default:
				return fmt.Errorf("jwt: can't covert string to %s", out.Type().String())
			}
		case reflect.Interface:
			if out.NumMethod() != 0 {
				return fmt.Errorf("jwt: can't covert string to %s", out.Type().String())
			}
			out.Set(reflect.ValueOf(in))
		case reflect.Struct:
			switch out.Type() {
			case urlType:
				u, err := url.Parse(in)
				if err != nil {
					return fmt.Errorf("jwt: failed to parse url: %w", err)
				}
				out.Set(reflect.ValueOf(*u))
			case bigIntType:
				b, err := b64.DecodeString(in)
				if err != nil {
					return fmt.Errorf("jwt: failed to decode base64url string: %w", err)
				}
				var bi big.Int
				bi.SetBytes(b)
				out.Set(reflect.ValueOf(bi))
			default:
				return fmt.Errorf("jwt: can't covert string to %s", out.Type().String())
			}
		default:
			return fmt.Errorf("jwt: can't covert string to %s", out.Type().String())
		}
	case float64:
		switch out.Kind() {
		case reflect.Interface:
			if out.NumMethod() != 0 {
				return fmt.Errorf("jwt: can't covert number to %s", out.Type().String())
			}
			out.Set(reflect.ValueOf(in))
		case reflect.Float32, reflect.Float64:
			if out.OverflowFloat(in) {
				return fmt.Errorf("jwt: failed to convert number: overflow")
			}
			out.SetFloat(in)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			i, f := math.Modf(in)
			if f != 0 || i > math.MaxInt64 || i < math.MinInt64 || out.OverflowInt(int64(i)) {
				return fmt.Errorf("jwt: failed to convert number: overflow")
			}
			out.SetInt(int64(i))
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			i, f := math.Modf(in)
			if f != 0 || i > math.MaxUint64 || i < 0 || out.OverflowUint(uint64(i)) {
				return fmt.Errorf("jwt: failed to convert number: overflow")
			}
			out.SetUint(uint64(i))
		default:
			return fmt.Errorf("jwt: can't covert number to %s", out.Type().String())
		}
	case json.Number:
		switch out.Kind() {
		case reflect.Interface:
			if out.NumMethod() != 0 {
				return fmt.Errorf("jwt: can't covert string to %s", out.Type().String())
			}
			out.Set(reflect.ValueOf(in))
		case reflect.Float32, reflect.Float64:
			f, err := in.Float64()
			if err != nil || out.OverflowFloat(f) {
				return fmt.Errorf("jwt: failed to convert number: overflow")
			}
			out.SetFloat(f)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			i, err := in.Int64()
			if err != nil || out.OverflowInt(int64(i)) {
				return fmt.Errorf("jwt: failed to convert number: overflow")
			}
			out.SetInt(int64(i))
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			i, err := strconv.ParseUint(string(in), 10, 64)
			if err == nil || out.OverflowUint(uint64(i)) {
				return fmt.Errorf("jwt: failed to convert number: overflow")
			}
			out.SetUint(uint64(i))
		case reflect.Struct:
			switch out.Type() {
			case timeType:
				var t jsonutils.NumericDate
				if err := t.UnmarshalJSON([]byte(in)); err != nil {
					return fmt.Errorf("jwt: failed to parse date time: %w", err)
				}
				out.Set(reflect.ValueOf(t.Time))
			default:
				return fmt.Errorf("jwt: can't covert number to %s", out.Type().String())
			}
		default:
			return fmt.Errorf("jwt: can't covert number to %s", out.Type().String())
		}
	case nil:
		switch out.Kind() {
		case reflect.Interface, reflect.Ptr, reflect.Map, reflect.Slice:
			out.Set(reflect.Zero(out.Type()))
			// otherwise, ignore null for primitives
		}
	case bool:
		switch out.Kind() {
		case reflect.Bool:
			out.SetBool(in)
		case reflect.Interface:
			if out.NumMethod() != 0 {
				return fmt.Errorf("jwt: can't covert boolean to %s", out.Type().String())
			}
			out.Set(reflect.ValueOf(in))
		default:
			return fmt.Errorf("jwt: can't covert boolean to %s", out.Type().String())
		}
	case map[string]any:
		switch out.Kind() {
		case reflect.Struct:
			for key, value := range in {
				fields := cachedTypeFields(out.Type())
				var f *field
				for i := range fields {
					ff := &fields[i]
					if ff.name == key {
						f = ff
						break
					}
				}
				if f != nil {
					subv := out
					for _, i := range f.index {
						if subv.Kind() == reflect.Ptr {
							if subv.IsNil() {
								if !subv.CanSet() {
									return fmt.Errorf("jwt: cannot set pointer to unexported struct: %v", subv.Type().Elem())
								}
								subv.Set(reflect.New(subv.Type().Elem()))
							}
							subv = subv.Elem()
						}
						subv = subv.Field(i)
					}
					if err := decode(value, subv); err != nil {
						return err
					}
				}
			}
		case reflect.Map:
			t := out.Type()
			kt := t.Key()
			if out.IsNil() {
				out.Set(reflect.MakeMapWithSize(t, len(in)))
			}
			elemType := out.Type().Elem()
			for k, v := range in {
				subv := reflect.New(elemType).Elem()
				if err := decode(v, subv); err != nil {
					return err
				}
				var kv reflect.Value
				switch {
				case kt.Kind() == reflect.String:
					kv = reflect.ValueOf(k).Convert(kt)
				}
				out.SetMapIndex(kv, subv)
			}
		case reflect.Interface:
			if out.NumMethod() != 0 {
				return fmt.Errorf("jwt: can't covert object to %s", out.Type().String())
			}
			out.Set(reflect.ValueOf(in))
		default:
			return fmt.Errorf("jwt: can't covert object to %s", out.Type().String())
		}
	case []any:
		switch out.Kind() {
		case reflect.Slice:
			// Grow slice if necessary
			if len(in) > out.Cap() {
				newout := reflect.MakeSlice(out.Type(), len(in), len(in))
				out.Set(newout)
			}
			out.SetLen(len(in))
			for i, v := range in {
				if err := decode(v, out.Index(i)); err != nil {
					return err
				}
			}
		case reflect.Interface:
			if out.NumMethod() != 0 {
				return fmt.Errorf("jwt: can't covert object to %s", out.Type().String())
			}
			out.Set(reflect.ValueOf(in))
		default:
			return fmt.Errorf("jwt: can't covert array to %s", out.Type().String())
		}
	default:
		return fmt.Errorf("jwt: invalid decode type: %s", reflect.TypeOf(in).String())
	}
	return nil
}

// A field represents a single field found in a struct.
type field struct {
	name  string
	index []int
	typ   reflect.Type
}

func typeFields(t reflect.Type) []field {
	// Anonymous fields to explore at the current level and the next.
	current := []field{}
	next := []field{{typ: t}}

	// Count of queued names for current level and the next.
	var count map[reflect.Type]int
	nextCount := map[reflect.Type]int{}

	// Types already visited at an earlier level.
	visited := map[reflect.Type]bool{}

	// Fields found.
	var fields []field

	for len(next) > 0 {
		current, next = next, current[:0]
		count, nextCount = nextCount, map[reflect.Type]int{}

		for _, f := range current {
			if visited[f.typ] {
				continue
			}
			visited[f.typ] = true

			// Scan f.typ for fields to include.
			for i := 0; i < f.typ.NumField(); i++ {
				sf := f.typ.Field(i)
				isUnexported := sf.PkgPath != ""
				if sf.Anonymous {
					t := sf.Type
					if t.Kind() == reflect.Ptr {
						t = t.Elem()
					}
					if isUnexported && t.Kind() != reflect.Struct {
						// Ignore embedded fields of unexported non-struct types.
						continue
					}
					// Do not ignore embedded fields of unexported struct types
					// since they may have exported fields.
				} else if isUnexported {
					// Ignore unexported non-embedded fields.
					continue
				}

				tag := sf.Tag.Get("jwt")

				index := make([]int, len(f.index)+1)
				copy(index, f.index)
				index[len(f.index)] = i

				ft := sf.Type
				if ft.Name() == "" && ft.Kind() == reflect.Ptr {
					// Follow pointer.
					ft = ft.Elem()
				}

				if !sf.Anonymous || ft.Kind() != reflect.Struct {
					if tag == "" {
						continue
					}
					fields = append(fields, field{
						name:  tag,
						index: index,
						typ:   sf.Type,
					})
					if count[f.typ] > 1 {
						fields = append(fields, fields[len(fields)-1])
					}
					continue
				}

				// Record new anonymous struct to explore in next round.
				nextCount[ft]++
				if nextCount[ft] == 1 {
					next = append(next, field{
						name:  ft.Name(),
						index: index,
						typ:   ft,
					})
				}
			}
		}
	}
	return fields
}

var fieldCache sync.Map // map[reflect.Type][]field

// cachedTypeFields is like typeFields but uses a cache to avoid repeated work.
func cachedTypeFields(t reflect.Type) []field {
	if f, ok := fieldCache.Load(t); ok {
		return f.([]field)
	}
	f, _ := fieldCache.LoadOrStore(t, typeFields(t))
	return f.([]field)
}
