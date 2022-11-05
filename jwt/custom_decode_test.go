package jwt

import (
	"encoding/json"
	"math/big"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/shogo82148/pointer"
)

func TestDecodeCustom(t *testing.T) {
	type MyClaims struct {
		String    string   `jwt:"string"`
		Strings   []string `jwt:"strings"`
		Int       int      `jwt:"int"`
		Int8      int8     `jwt:"int8"`
		Int16     int16    `jwt:"int16"`
		Int32     int32    `jwt:"int32"`
		Int64     int64    `jwt:"int64"`
		Uint      int      `jwt:"uint"`
		Uint8     int8     `jwt:"uint8"`
		Uint16    int16    `jwt:"uint16"`
		Uint32    int32    `jwt:"uint32"`
		Uint64    int64    `jwt:"uint64"`
		Float32   float32  `jwt:"float32"`
		Float64   float64  `jwt:"float64"`
		True      bool     `jwt:"true"`
		False     bool     `jwt:"false"`
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
				"strings":   "strings",
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
				Strings:   []string{"strings"},
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

		// byte sequence
		{
			in: map[string]any{
				"bytes": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
					"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
			},
			out: new(struct {
				Bytes []byte `jwt:"bytes"`
			}),
			want: &struct {
				Bytes []byte `jwt:"bytes"`
			}{
				Bytes: []byte(`{"iss":"joe",` + "\r\n" +
					` "exp":1300819380,` + "\r\n" +
					` "http://example.com/is_root":true}`),
			},
		},

		// time
		{
			in: map[string]any{
				"time": json.Number("1300819380"),
			},
			out: new(struct {
				Time time.Time `jwt:"time"`
			}),
			want: &struct {
				Time time.Time `jwt:"time"`
			}{
				Time: time.Unix(1300819380, 0).UTC(),
			},
		},

		// url
		{
			in: map[string]any{
				"url": "http://example.com/is_root",
			},
			out: new(struct {
				URL *url.URL `jwt:"url"`
			}),
			want: &struct {
				URL *url.URL `jwt:"url"`
			}{
				URL: &url.URL{
					Scheme: "http",
					Host:   "example.com",
					Path:   "/is_root",
				},
			},
		},

		// big.Int
		{
			in: map[string]any{
				"x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			out: new(struct {
				X *big.Int `jwt:"x"`
			}),
			want: &struct {
				X *big.Int `jwt:"x"`
			}{
				X: new(big.Int).SetBytes([]byte{
					0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
					0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
				}),
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
