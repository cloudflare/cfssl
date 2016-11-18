package tls

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

type testStruct struct {
	Data   []byte `tls:"minlen:2,maxlen:4"`
	IntVal uint16
	Other  [4]byte
	Enum   Enum `tls:"size:2"`
}

type testVariant struct {
	Which Enum    `tls:"size:1"`
	Val16 *uint16 `tls:"selector:Which,val:0"`
	Val32 *uint32 `tls:"selector:Which,val:1"`
}

type testTwoVariants struct {
	Which    Enum    `tls:"size:1"`
	Val16    *uint16 `tls:"selector:Which,val:0"`
	Val32    *uint32 `tls:"selector:Which,val:1"`
	Second   Enum    `tls:"size:1"`
	Second16 *uint16 `tls:"selector:Second,val:0"`
	Second32 *uint32 `tls:"selector:Second,val:1"`
}

// Check that library users can define their own Enum types.
type aliasEnum Enum
type testAliasEnum struct {
	Val   aliasEnum `tls:"size:1"`
	Val16 *uint16   `tls:"selector:Val,val:1"`
	Val32 *uint32   `tls:"selector:Val,val:2"`
}

type testNonByteSlice struct {
	Vals []uint16 `tls:"minlen:2,maxlen:6"`
}

type testSliceOfStructs struct {
	Vals []testVariant `tls:"minlen:0,maxlen:100"`
}

type testInnerType struct {
	Val []byte `tls:"minlen:0,maxlen:65535"`
}

type testSliceOfSlices struct {
	Inners []testInnerType `tls:"minlen:0,maxlen:65535"`
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	thing := testStruct{Data: []byte{0x01, 0x02, 0x03}, IntVal: 42, Other: [4]byte{1, 2, 3, 4}, Enum: 17}
	data, err := Marshal(thing)
	if err != nil {
		t.Fatalf("Failed to Marshal(%+v): %s", thing, err.Error())
	}
	var other testStruct
	rest, err := Unmarshal(data, &other)
	if err != nil {
		t.Fatalf("Failed to Unmarshal(%s)", hex.EncodeToString(data))
	}
	if len(rest) > 0 {
		t.Errorf("Data left over after Unmarshal(%s): %s", hex.EncodeToString(data), hex.EncodeToString(rest))
	}
}

func TestFieldTagToFieldInfo(t *testing.T) {
	var tests = []struct {
		tag    string
		want   *fieldInfo
		errstr string
	}{
		{"", nil, ""},
		{"bogus", nil, ""},
		{"also,bogus", nil, ""},
		{"also,bogus:99", nil, ""},
		{"maxval:1xyz", nil, ""},
		{"maxval:1", &fieldInfo{count: 1, countSet: true}, ""},
		{"maxval:255", &fieldInfo{count: 1, countSet: true}, ""},
		{"maxval:256", &fieldInfo{count: 2, countSet: true}, ""},
		{"maxval:65535", &fieldInfo{count: 2, countSet: true}, ""},
		{"maxval:65536", &fieldInfo{count: 3, countSet: true}, ""},
		{"maxval:16777215", &fieldInfo{count: 3, countSet: true}, ""},
		{"maxval:16777216", &fieldInfo{count: 4, countSet: true}, ""},
		{"maxval:16777216", &fieldInfo{count: 4, countSet: true}, ""},
		{"maxval:4294967295", &fieldInfo{count: 4, countSet: true}, ""},
		{"maxval:4294967296", &fieldInfo{count: 5, countSet: true}, ""},
		{"maxval:1099511627775", &fieldInfo{count: 5, countSet: true}, ""},
		{"maxval:1099511627776", &fieldInfo{count: 6, countSet: true}, ""},
		{"maxval:281474976710655", &fieldInfo{count: 6, countSet: true}, ""},
		{"maxval:281474976710656", &fieldInfo{count: 7, countSet: true}, ""},
		{"maxval:72057594037927935", &fieldInfo{count: 7, countSet: true}, ""},
		{"maxval:72057594037927936", &fieldInfo{count: 8, countSet: true}, ""},
		{"minlen:1x", nil, ""},
		{"maxlen:1x", nil, ""},
		{"maxlen:1", &fieldInfo{count: 1, countSet: true, maxlen: 1}, ""},
		{"maxlen:255", &fieldInfo{count: 1, countSet: true, maxlen: 255}, ""},
		{"maxlen:65535", &fieldInfo{count: 2, countSet: true, maxlen: 65535}, ""},
		{"minlen:65530,maxlen:65535", &fieldInfo{count: 2, countSet: true, minlen: 65530, maxlen: 65535}, ""},
		{"maxlen:65535,minlen:65530", &fieldInfo{count: 2, countSet: true, minlen: 65530, maxlen: 65535}, ""},
		{"minlen:65536,maxlen:65535", nil, "inverted"},
		{"maxlen:16777215", &fieldInfo{count: 3, countSet: true, maxlen: 16777215}, ""},
		{"maxlen:281474976710655", &fieldInfo{count: 6, countSet: true, maxlen: 281474976710655}, ""},
		{"maxlen:72057594037927936", &fieldInfo{count: 8, countSet: true, maxlen: 72057594037927936}, ""},
		{"size:0", nil, "unknown size"},
		{"size:1", &fieldInfo{count: 1, countSet: true}, ""},
		{"size:2", &fieldInfo{count: 2, countSet: true}, ""},
		{"size:3", &fieldInfo{count: 3, countSet: true}, ""},
		{"size:4", &fieldInfo{count: 4, countSet: true}, ""},
		{"size:5", &fieldInfo{count: 5, countSet: true}, ""},
		{"size:6", &fieldInfo{count: 6, countSet: true}, ""},
		{"size:7", &fieldInfo{count: 7, countSet: true}, ""},
		{"size:8", &fieldInfo{count: 8, countSet: true}, ""},
		{"size:9", nil, "too large"},
		{"size:1x", nil, ""},
		{"size:1,val:9", nil, "selector value"},
		{"selector:Bob,val:x9", &fieldInfo{selector: "Bob"}, ""},
		{"selector:Fred,val:1", &fieldInfo{selector: "Fred", val: 1}, ""},
		{"val:9,selector:Fred,val:1", &fieldInfo{selector: "Fred", val: 1}, ""},
	}
	for _, test := range tests {
		got, err := fieldTagToFieldInfo(test.tag, "")
		if test.errstr != "" {
			if err == nil {
				t.Errorf("fieldTagToFieldInfo('%v')=%+v,nil; want error %q", test.tag, got, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("fieldTagToFieldInfo('%v')=nil,%q; want error %q", test.tag, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("fieldTagToFieldInfo('%v')=nil,%q; want %+v", test.tag, err.Error(), test.want)
		} else if !reflect.DeepEqual(got, test.want) {
			t.Errorf("fieldTagToFieldInfo('%v')=%+v,nil; want %+v", test.tag, got, test.want)
		}
	}
}

// Can't take the address of a numeric constant so use helper functions
func newByte(n byte) *byte       { return &n }
func newUint8(n uint8) *uint8    { return &n }
func newUint16(n uint16) *uint16 { return &n }
func newUint24(n Uint24) *Uint24 { return &n }
func newUint32(n uint32) *uint32 { return &n }
func newUint64(n uint64) *uint64 { return &n }
func newInt16(n int16) *int16    { return &n }
func newEnum(n Enum) *Enum       { return &n }

func TestUnmarshalMarshalWithParamsRoundTrip(t *testing.T) {
	var tests = []struct {
		data   string // hex encoded
		params string
		item   interface{}
	}{
		{"00", "", newUint8(0)},
		{"03", "", newByte(3)},
		{"0101", "", newUint16(0x0101)},
		{"010203", "", newUint24(0x010203)},
		{"000000", "", newUint24(0x00)},
		{"00000009", "", newUint32(0x09)},
		{"0000000901020304", "", newUint64(0x0901020304)},
		{"030405", "", &[3]byte{3, 4, 5}},
		{"03", "", &[1]byte{3}},
		{"0001", "size:2", newEnum(1)},
		{"0100000001", "size:5", newEnum(0x100000001)},
		{"12", "maxval:18", newEnum(18)},
		// Note that maxval is just used to give enum size; it's not policed
		{"20", "maxval:18", newEnum(32)},
		{"020a0b", "minlen:1,maxlen:5", &[]byte{0xa, 0xb}},
		{"020a0b0101010203040011", "", &testStruct{Data: []byte{0xa, 0xb}, IntVal: 0x101, Other: [4]byte{1, 2, 3, 4}, Enum: 17}},
		{"000102", "", &testVariant{Which: 0, Val16: newUint16(0x0102)}},
		{"0101020304", "", &testVariant{Which: 1, Val32: newUint32(0x01020304)}},
		{"0001020104030201", "", &testTwoVariants{Which: 0, Val16: newUint16(0x0102), Second: 1, Second32: newUint32(0x04030201)}},
		{"06010102020303", "", &testNonByteSlice{Vals: []uint16{0x101, 0x202, 0x303}}},
		{"00", "", &testSliceOfStructs{Vals: []testVariant{}}},
		{"080001020101020304", "",
			&testSliceOfStructs{
				Vals: []testVariant{
					testVariant{Which: 0, Val16: newUint16(0x0102)},
					testVariant{Which: 1, Val32: newUint32(0x01020304)},
				},
			},
		},
		{"000a00030102030003040506", "",
			&testSliceOfSlices{
				Inners: []testInnerType{
					testInnerType{Val: []byte{1, 2, 3}},
					testInnerType{Val: []byte{4, 5, 6}},
				},
			},
		},
		{"011011", "", &testAliasEnum{Val: 1, Val16: newUint16(0x1011)}},
		{"0403", "", &SignatureAndHashAlgorithm{Hash: SHA256, Signature: ECDSA}},
		{"04030003010203", "",
			&DigitallySigned{
				Algorithm: SignatureAndHashAlgorithm{Hash: SHA256, Signature: ECDSA},
				Signature: []byte{1, 2, 3},
			},
		},
	}
	for _, test := range tests {
		inVal := reflect.ValueOf(test.item).Elem()
		pv := reflect.New(reflect.TypeOf(test.item).Elem())
		val := pv.Interface()
		inData, _ := hex.DecodeString(test.data)
		if _, err := UnmarshalWithParams(inData, val, test.params); err != nil {
			t.Errorf("Unmarshal(%s)=nil,%q; want %+v", test.data, err.Error(), inVal)
		} else if !reflect.DeepEqual(val, test.item) {
			t.Errorf("Unmarshal(%s)=%+v,nil; want %+v", test.data, reflect.ValueOf(val).Elem(), inVal)
		}

		if data, err := MarshalWithParams(inVal.Interface(), test.params); err != nil {
			t.Errorf("Marshal(%+v)=nil,%q; want %s", inVal, err.Error(), test.data)
		} else if !bytes.Equal(data, inData) {
			t.Errorf("Marshal(%+v)=%s,nil; want %s", inVal, hex.EncodeToString(data), test.data)
		}
	}
}

type testInvalidFieldTag struct {
	Data []byte `tls:"minlen:3,maxlen:2"`
}

type testDuplicateSelectorVal struct {
	Which  Enum    `tls:"size:1"`
	Val    *uint16 `tls:"selector:Which,val:0"`
	DupVal *uint32 `tls:"selector:Which"` // implicit val:0
}

type testMissingSelector struct {
	Val *uint16 `tls:"selector:Missing,val:0"`
}

type testChoiceNotPointer struct {
	Which Enum   `tls:"size:1"`
	Val   uint16 `tls:"selector:Which,val:0"`
}

type nonEnumAlias uint16

func newNonEnumAlias(n nonEnumAlias) *nonEnumAlias { return &n }

func TestUnmarshalWithParamsFailures(t *testing.T) {
	var tests = []struct {
		data   string // hex encoded
		params string
		item   interface{}
		errstr string
	}{
		{"", "", newUint8(0), "truncated"},
		{"0x01", "", newUint16(0x0101), "truncated"},
		{"0103", "", newUint24(0x010203), "truncated"},
		{"00", "", newUint24(0x00), "truncated"},
		{"000009", "", newUint32(0x09), "truncated"},
		{"00000901020304", "", newUint64(0x0901020304), "truncated"},
		{"0102", "", newInt16(0x0102), "unsupported type"}, // TLS encoding only supports unsigned integers
		{"0607", "", &[3]byte{6, 7, 8}, "truncated array"},
		{"01010202", "", &[3]uint16{0x101, 0x202}, "unsupported array"},
		{"01", "", newEnum(1), "no field size"},
		{"00", "size:2", newEnum(0), "truncated"},
		{"00", "size:9", newEnum(0), "too large"},
		{"020a0b", "minlen:4,maxlen:8", &[]byte{0x0a, 0x0b}, "too small"},
		{"040a0b0c0d", "minlen:1,maxlen:3", &[]byte{0x0a, 0x0b, 0x0c, 0x0d}, "too large"},
		{"020a0b", "minlen:8,maxlen:6", &[]byte{0x0a, 0x0b}, "inverted"},
		{"020a", "minlen:0,maxlen:6", &[]byte{0x0a, 0x0b}, "truncated"},
		{"02", "minlen:0,maxlen:6", &[]byte{0x0a, 0x0b}, "truncated"},
		{"0001", "minlen:0,maxlen:256", &[]byte{0x0a, 0x0b}, "truncated"},
		{"020a", "minlen:0", &[]byte{0x0a, 0x0b}, "unknown size"},
		{"020a", "", &[]byte{0x0a, 0x0b}, "no field size information"},
		{"020a0b", "", &testInvalidFieldTag{}, "range inverted"},
		{"020a0b01010102030400", "",
			&testStruct{Data: []byte{0xa, 0xb}, IntVal: 0x101, Other: [4]byte{1, 2, 3, 4}, Enum: 17}, "truncated"},
		{"010102", "", &testVariant{Which: 1, Val32: newUint32(0x01020304)}, "truncated"},
		{"092122", "", &testVariant{Which: 0, Val16: newUint16(0x2122)}, "unhandled value for selector"},
		{"0001020304", "", &testDuplicateSelectorVal{Which: 0, Val: newUint16(0x0102)}, "duplicate selector value"},
		{"0102", "", &testMissingSelector{Val: newUint16(1)}, "selector not seen"},
		{"000007", "", &testChoiceNotPointer{Which: 0, Val: 7}, "choice field not a pointer type"},
		{"05010102020303", "", &testNonByteSlice{Vals: []uint16{0x101, 0x202, 0x303}}, "truncated"},
		{"0101", "size:2", newNonEnumAlias(0x0102), "unsupported type"},
		{"0403010203", "",
			&DigitallySigned{
				Algorithm: SignatureAndHashAlgorithm{Hash: SHA256, Signature: ECDSA},
				Signature: []byte{1, 2, 3}}, "truncated"},
	}
	for _, test := range tests {
		pv := reflect.New(reflect.TypeOf(test.item).Elem())
		val := pv.Interface()
		in, _ := hex.DecodeString(test.data)
		if _, err := UnmarshalWithParams(in, val, test.params); err == nil {
			t.Errorf("Unmarshal(%s)=%+v,nil; want error %q", test.data, reflect.ValueOf(val).Elem(), test.errstr)
		} else if !strings.Contains(err.Error(), test.errstr) {
			t.Errorf("Unmarshal(%s)=nil,%q; want error %q", test.data, err.Error(), test.errstr)
		}
	}
}

func TestMarshalWithParamsFailures(t *testing.T) {
	var tests = []struct {
		item   interface{}
		params string
		errstr string
	}{
		{Uint24(0x1000000), "", "overflow"},
		{int16(0x0102), "", "unsupported type"}, // All TLS ints are unsigned
		{Enum(1), "", "field tag missing"},
		{Enum(256), "size:1", "too large"},
		{Enum(256), "maxval:255", "too large"},
		{Enum(2), "", "field tag missing"},
		{Enum(256), "size:9", "too large"},
		{[]byte{0xa, 0xb, 0xc, 0xd}, "minlen:1,maxlen:3", "too large"},
		{[]byte{0xa, 0xb, 0xc, 0xd}, "minlen:6,maxlen:13", "too small"},
		{[]byte{0xa, 0xb, 0xc, 0xd}, "minlen:6,maxlen:3", "inverted"},
		{[]byte{0xa, 0xb, 0xc, 0xd}, "minlen:6", "unknown size"},
		{[]byte{0xa, 0xb, 0xc, 0xd}, "", "field tag missing"},
		{[3]uint16{0x101, 0x202}, "", "unsupported array"},
		{testInvalidFieldTag{}, "", "inverted"},
		{testStruct{Data: []byte{0xa}, IntVal: 0x101, Other: [4]byte{1, 2, 3, 4}, Enum: 17}, "", "too small"},
		{testVariant{Which: 0, Val32: newUint32(0x01020304)}, "", "chosen field is nil"},
		{testVariant{Which: 0, Val16: newUint16(11), Val32: newUint32(0x01020304)}, "", "unchosen field is non-nil"},
		{testVariant{Which: 3}, "", "unhandled value for selector"},
		{testMissingSelector{Val: newUint16(1)}, "", "selector not seen"},
		{testChoiceNotPointer{Which: 0, Val: 7}, "", "choice field not a pointer"},
		{testDuplicateSelectorVal{Which: 0, Val: newUint16(1)}, "", "duplicate selector value"},
		{testNonByteSlice{Vals: []uint16{1, 2, 3, 4}}, "", "too large"},
		{testSliceOfStructs{[]testVariant{testVariant{Which: 3}}}, "", "unhandled value for selector"},
		{nonEnumAlias(0x0102), "", "unsupported type"},
	}
	for _, test := range tests {
		if data, err := MarshalWithParams(test.item, test.params); err == nil {
			t.Errorf("Marshal(%+v)=%x,nil; want error %q", test.item, data, test.errstr)
		} else if !strings.Contains(err.Error(), test.errstr) {
			t.Errorf("Marshal(%+v)=nil,%q; want error %q", test.item, err.Error(), test.errstr)
		}
	}
}
