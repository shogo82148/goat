package jwt

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/shogo82148/pointer"
)

func TestDecodeCustom(t *testing.T) {
	type MyClaims struct {
		String    string  `jwt:"string"`
		Int       int     `jwt:"int"`
		Int8      int8    `jwt:"int8"`
		Int16     int16   `jwt:"int16"`
		Int32     int32   `jwt:"int32"`
		Int64     int64   `jwt:"int64"`
		Uint      int     `jwt:"uint"`
		Uint8     int8    `jwt:"uint8"`
		Uint16    int16   `jwt:"uint16"`
		Uint32    int32   `jwt:"uint32"`
		Uint64    int64   `jwt:"uint64"`
		Float32   float32 `jwt:"float32"`
		Float64   float64 `jwt:"float64"`
		True      bool    `jwt:"true"`
		False     bool    `jwt:"false"`
		NotTagged string
		private   string
	}

	type Embed0 struct {
		Foo string `jwt:"foo"`
	}
	type Embed0a struct {
		Foo1a string `jwt:"foo1a"`
	}
	type Parent struct {
		Embed0
		*Embed0a
		Bar string `jwt:"bar"`
	}

	type Loop struct {
		Loop1 int `jwt:"loop1"`
		Loop2 int `jwt:"loop2"`
		*Loop
	}

	type Interface struct {
		String  any `jwt:"string"`
		Number  any `jwt:"number"`
		Object  any `jwt:"object"`
		Array   any `jwt:"array"`
		Boolean any `jwt:"boolean"`
		Null    any `jwt:"null"`
	}

	cases := []struct {
		in   map[string]any
		out  any
		want any
	}{
		{
			in: map[string]any{
				"string":    "foobar",
				"int":       1.0,
				"int8":      8.0,
				"int16":     16.0,
				"int32":     32.0,
				"int64":     64.0,
				"uint":      1.0,
				"uint8":     8.0,
				"uint16":    16.0,
				"uint32":    32.0,
				"uint64":    64.0,
				"float32":   0.5,
				"float64":   0.5,
				"true":      true,
				"false":     false,
				"NotTagged": "NotTagged",
				"private":   "private",
			},
			out: new(MyClaims),
			want: &MyClaims{
				String:    "foobar",
				Int:       1,
				Int8:      8,
				Int16:     16,
				Int32:     32,
				Int64:     64,
				Uint:      1,
				Uint8:     8,
				Uint16:    16,
				Uint32:    32,
				Uint64:    64,
				Float32:   0.5,
				Float64:   0.5,
				True:      true,
				False:     false,
				NotTagged: "",
				private:   "",
			},
		},

		// test for json.Number
		{
			in: map[string]any{
				"int":     json.Number("1"),
				"int8":    json.Number("8"),
				"int16":   json.Number("16"),
				"int32":   json.Number("32"),
				"int64":   json.Number("64"),
				"uint":    json.Number("1"),
				"uint8":   json.Number("8"),
				"uint16":  json.Number("16"),
				"uint32":  json.Number("32"),
				"uint64":  json.Number("64"),
				"float32": json.Number("0.5"),
				"float64": json.Number("0.5"),
			},
			out: new(MyClaims),
			want: &MyClaims{
				Int:     1,
				Int8:    8,
				Int16:   16,
				Int32:   32,
				Int64:   64,
				Uint:    1,
				Uint8:   8,
				Uint16:  16,
				Uint32:  32,
				Uint64:  64,
				Float32: 0.5,
				Float64: 0.5,
			},
		},

		// embed struct
		{
			in: map[string]any{
				"foo":   "foo",
				"foo1a": "foo1a",
				"bar":   "bar",
			},
			out: new(Parent),
			want: &Parent{
				Embed0: Embed0{
					Foo: "foo",
				},
				Embed0a: &Embed0a{
					Foo1a: "foo1a",
				},
				Bar: "bar",
			},
		},

		// Loop
		{
			in: map[string]any{
				"loop1": 1.0,
				"loop2": 2.0,
			},
			out: new(Loop),
			want: &Loop{
				Loop1: 1,
				Loop2: 2,
			},
		},

		// Reference
		{
			in: map[string]any{
				"string": "string",
				"number": json.Number("123"),
				"object": map[string]any{
					"foo": "bar",
				},
				"array":   []any{"1", "2", "3"},
				"boolean": true,
				"null":    nil,
			},
			out: new(Interface),
			want: &Interface{
				String: "string",
				Number: json.Number("123"),
				Object: map[string]any{
					"foo": "bar",
				},
				Array:   []any{"1", "2", "3"},
				Boolean: true,
				Null:    nil,
			},
		},

		// pointers
		{
			in: map[string]any{
				"ptr": "value",
			},
			out: new(struct {
				Ptr *****string `jwt:"ptr"`
			}),
			want: &struct {
				Ptr *****string `jwt:"ptr"`
			}{
				Ptr: pointer.Ptr(pointer.Ptr(pointer.Ptr(pointer.Ptr(pointer.Ptr("value"))))),
			},
		},
	}

	for i, tc := range cases {
		claims := &Claims{
			Raw: tc.in,
		}
		if err := claims.DecodeCustom(tc.out); err != nil {
			t.Errorf("%d: error: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(tc.out, tc.want) {
			t.Errorf("%d: want %#v, got %#v", i, tc.want, tc.out)
		}
	}
}
