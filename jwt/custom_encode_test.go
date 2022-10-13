package jwt

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEncodeCustom(t *testing.T) {
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

	cases := []struct {
		in   any
		want map[string]any
	}{
		{
			in: &MyClaims{
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
				NotTagged: "NotTagged",
				private:   "private",
			},
			want: map[string]any{
				"string":  "foobar",
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
				"true":    true,
				"false":   false,
			},
		},
		{
			in: &Parent{
				Embed0: Embed0{
					Foo: "foo",
				},
				Embed0a: &Embed0a{
					Foo1a: "foo1a",
				},
				Bar: "bar",
			},
			want: map[string]any{
				"foo":   "foo",
				"foo1a": "foo1a",
				"bar":   "bar",
			},
		},
	}
	for i, tc := range cases {
		claims := &Claims{}
		if err := claims.EncodeCustom(tc.in); err != nil {
			t.Errorf("%d: error: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(claims.Raw, tc.want) {
			t.Errorf("%d: want %#v, got %#v", i, tc.want, claims.Raw)
		}
	}
}
