package jsonutils

import (
	"bytes"
	"testing"
)

func TestDecoder_Decode(t *testing.T) {
	v := "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75" +
		"aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
	raw := map[string]any{
		"k": v,
	}
	d := NewDecoder("jsonutils", raw)
	got := d.Decode(v, "k")
	want := []byte{
		0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc,
		0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
		0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28,
		0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
		0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef,
		0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
		0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08,
		0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
	}
	if !bytes.Equal(want, got) {
		t.Errorf("unexpected key value: want %x, got %x", want, got)
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestDecoder_Decode_Error(t *testing.T) {
	v := "!!INVALID BASE64!!"
	raw := map[string]any{
		"k": v,
	}
	d := NewDecoder("jsonutils", raw)
	d.Decode(v, "k")
	if err := d.Err(); err == nil {
		t.Error("want some error, got nil")
	}
}

func TestDecoder_Has(t *testing.T) {
	raw := map[string]any{
		"k": "v",
	}
	d := NewDecoder("jsonutils", raw)
	if !d.Has("k") {
		t.Error("want true, but got false")
	}
	if d.Has("K") {
		t.Error("want false, but got true")
	}
}

func TestDecoder_GetString(t *testing.T) {
	raw := map[string]any{
		"string": "it is a string",
		"number": 1.0,
	}

	// succeed
	d := NewDecoder("jsonutils", raw)
	if v, ok := d.GetString("string"); !ok || v != "it is a string" {
		t.Error("want a string, but failed")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	// key not found
	if _, ok := d.GetString("another_string"); ok {
		t.Error("want not ok, but ok")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	// type error
	if _, ok := d.GetString("number"); ok {
		t.Error("want not ok, but got")
	}
	if err := d.Err(); err == nil {
		t.Error("want some error, but not")
	}
}

func TestDecoder_MustString(t *testing.T) {
	var d *Decoder
	raw := map[string]any{
		"string": "it is a string",
		"number": 1.0,
	}

	// succeed
	d = NewDecoder("jsonutils", raw)
	if v := d.MustString("string"); v != "it is a string" {
		t.Error("want a string, but failed")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	// key not found
	d = NewDecoder("jsonutils", raw)
	if v := d.MustString("another_string"); v != "" {
		t.Errorf("want an empty string, but got %q", v)
	}
	if err := d.Err(); err == nil {
		t.Error("want some error, but not")
	}

	// type error
	d = NewDecoder("jsonutils", raw)
	if v := d.MustString("number"); v != "" {
		t.Errorf("want an empty string, but got %q", v)
	}
	if err := d.Err(); err == nil {
		t.Error("want some error, but not")
	}
}

func TestDecoder_GetArray(t *testing.T) {
	var d *Decoder
	raw := map[string]any{
		"array":  []any{},
		"string": "it is a string",
	}

	// succeed
	d = NewDecoder("jsonutils", raw)
	if v, ok := d.GetArray("array"); !ok || v == nil {
		t.Error("want an array, but not")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	// not found
	d = NewDecoder("jsonutils", raw)
	if _, ok := d.GetArray("another"); ok {
		t.Error("want not ok, but ok")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	// type error
	if _, ok := d.GetArray("string"); ok {
		t.Error("want not ok, but got")
	}
	if err := d.Err(); err == nil {
		t.Error("want some error, but not")
	}
}

func TestDecoder_MustArray(t *testing.T) {
	var d *Decoder
	raw := map[string]any{
		"array":  []any{},
		"string": "it is a string",
	}

	// succeed
	d = NewDecoder("jsonutils", raw)
	if v := d.MustArray("array"); v == nil {
		t.Error("want an array, but failed")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	// key not found
	d = NewDecoder("jsonutils", raw)
	if v := d.MustArray("not key"); v != nil {
		t.Errorf("want nil, but got %#v", v)
	}
	if err := d.Err(); err == nil {
		t.Error("want some error, but not")
	}

	// type error
	d = NewDecoder("jsonutils", raw)
	if v := d.MustArray("string"); v != nil {
		t.Errorf("want nil, but got %#v", v)
	}
	if err := d.Err(); err == nil {
		t.Error("want some error, but not")
	}
}

func TestDecoder_GetObject(t *testing.T) {
	var d *Decoder
	raw := map[string]any{
		"object": map[string]any{},
		"string": "it is a string",
	}

	// succeed
	d = NewDecoder("jsonutils", raw)
	if v, ok := d.GetObject("object"); !ok || v == nil {
		t.Error("want an object, but not")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	// not found
	d = NewDecoder("jsonutils", raw)
	if _, ok := d.GetObject("another"); ok {
		t.Error("want not ok, but ok")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	// type error
	if _, ok := d.GetObject("string"); ok {
		t.Error("want not ok, but got")
	}
	if err := d.Err(); err == nil {
		t.Error("want some error, but not")
	}
}

func TestDecoder_GetStringArray(t *testing.T) {
	var d *Decoder
	raw := map[string]any{
		"empty":        []any{},
		"string-array": []any{"string"},
		"number-array": []any{1.0},
		"string":       "string",
	}

	// succeed
	d = NewDecoder("jsonutils", raw)
	if v, ok := d.GetStringArray("empty"); !ok || v == nil {
		t.Error("want an array, but not")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	d = NewDecoder("jsonutils", raw)
	v, ok := d.GetStringArray("string-array")
	if !ok || v == nil {
		t.Error("want an array, but not")
	}
	if len(v) != 1 {
		t.Error("invalid length")
	}
	if v[0] != "string" {
		t.Error("invalid content")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}

	// type error: number array
	d = NewDecoder("jsonutils", raw)
	if _, ok := d.GetStringArray("number-array"); ok {
		t.Error("want not ok, but ok")
	}
	if err := d.Err(); err == nil {
		t.Error("want some error, but not")
	}

	// type error: string
	if _, ok := d.GetStringArray("string"); ok {
		t.Error("want not ok, but got")
	}
	if err := d.Err(); err == nil {
		t.Error("want some error, but not")
	}
}

func TestDecoder_GetBytes(t *testing.T) {
	v := "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75" +
		"aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
	raw := map[string]any{
		"k": v,
	}
	d := NewDecoder("jsonutils", raw)
	got, ok := d.GetBytes("k")
	if !ok {
		t.Error("want ok, got !ok")
	}
	want := []byte{
		0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc,
		0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
		0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28,
		0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
		0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef,
		0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
		0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08,
		0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
	}
	if !bytes.Equal(want, got) {
		t.Errorf("unexpected key value: want %x, got %x", want, got)
	}

	if _, ok := d.GetBytes("invalid"); ok {
		t.Error("want !ok, got ok")
	}

	if err := d.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestDecoder_MustBytes(t *testing.T) {
	v := "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75" +
		"aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
	raw := map[string]any{
		"k": v,
	}
	d := NewDecoder("jsonutils", raw)
	got := d.MustBytes("k")
	want := []byte{
		0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc,
		0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
		0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28,
		0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
		0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef,
		0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
		0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08,
		0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
	}
	if !bytes.Equal(want, got) {
		t.Errorf("unexpected key value: want %x, got %x", want, got)
	}

	if bytes := d.MustBytes("invalid"); bytes != nil {
		t.Errorf("want nil, got %#v", bytes)
	}

	if err := d.Err(); err == nil {
		t.Error("want some error, got nil")
	}
}

func TestDecoder_GetBigInt(t *testing.T) {
	// TODO
}

func TestDecoder_MustBigInt(t *testing.T) {
	// TODO
}

func TestDecoder_GetURL(t *testing.T) {
	// TODO
}

func TestDecoder_GetTime(t *testing.T) {
	// TODO
}

func TestDecoder_GetInt64(t *testing.T) {
	// TODO
}

func TestDecoder_MustInt64(t *testing.T) {
	// TODO
}
