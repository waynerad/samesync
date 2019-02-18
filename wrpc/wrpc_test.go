package wrpc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func testCompareByteArrays(t *testing.T, b1 []byte, b2 []byte, message string) {
	if len(b1) != len(b2) {
		t.Error("Byte arrays of of unequal length: " + message)
		return
	}
	for ii := 0; ii < len(b1); ii++ {
		if b1[ii] != b2[ii] {
			t.Error("Byte arrays differ: " + message)
			return
		}
	}
}

func testCompareUint64s(t *testing.T, n1 uint64, n2 uint64, message string) {
	if n1 != n2 {
		t.Error("Numbers are not equal: " + message)
	}
}

func testCompareInt64s(t *testing.T, n1 int64, n2 int64, message string) {
	if n1 != n2 {
		t.Error("Numbers are not equal: " + message)
	}
}

func TestEncodeUint(t *testing.T) {
	var number uint64

	// Test 1
	number = 0
	bytes := EncodeUint(number)
	expected := []byte{0}
	testCompareByteArrays(t, bytes, expected, "Uint test 1 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 1 decoding failed")

	// "Test 2"
	number = 1
	bytes = EncodeUint(number)
	expected = []byte{1, 1}
	testCompareByteArrays(t, bytes, expected, "Uint test 2 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 2 decoding failed 51")

	// Test 3
	number = 47
	bytes = EncodeUint(number)
	expected = []byte{1, 47}
	testCompareByteArrays(t, bytes, expected, "Uint test 3 encoding failed 57")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 3 decoding failed")

	// Test 4
	number = 255
	bytes = EncodeUint(number)
	expected = []byte{1, 255}
	testCompareByteArrays(t, bytes, expected, "Uint test 4 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 4 decoding failed")

	// Test 5
	number = 256
	bytes = EncodeUint(number)
	expected = []byte{2, 1, 0}
	testCompareByteArrays(t, bytes, expected, "Uint test 5 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 5 decoding failed")

	// Test 6
	number = 58295
	bytes = EncodeUint(number)
	expected = []byte{2, 227, 183}
	testCompareByteArrays(t, bytes, expected, "Uint test 6 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 6 decoding failed")

	// Test 7
	number = 65535
	bytes = EncodeUint(number)
	expected = []byte{2, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Uint test 7 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 8 decoding failed")

	// Test 8
	number = 65536
	bytes = EncodeUint(number)
	expected = []byte{3, 1, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Uint test 8 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 9 decoding failed")

	// Test 9
	number = 12543843
	bytes = EncodeUint(number)
	expected = []byte{3, 191, 103, 99}
	testCompareByteArrays(t, bytes, expected, "Uint test 9 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 9 decoding failed")

	// Test 10
	number = 16777215
	bytes = EncodeUint(number)
	expected = []byte{3, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Uint test 10 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 10 decoding failed")

	// Test 11
	number = 16777216
	bytes = EncodeUint(number)
	expected = []byte{4, 1, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Uint test 11 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 11 decoding failed")

	// Test 12
	number = 1698780716
	bytes = EncodeUint(number)
	expected = []byte{4, 101, 65, 86, 44}
	testCompareByteArrays(t, bytes, expected, "Uint test 12 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 12 decoding failed")

	// Test 13
	number = 4294967295
	bytes = EncodeUint(number)
	expected = []byte{4, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Uint test 13 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 13 decoding failed")

	// Test 14
	number = 4294967296
	bytes = EncodeUint(number)
	expected = []byte{5, 1, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Uint test 14 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 14 decoding failed")

	// Test 15
	number = 1062657006408
	bytes = EncodeUint(number)
	expected = []byte{5, 247, 107, 75, 27, 72}
	testCompareByteArrays(t, bytes, expected, "Uint test 15 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 15 decoding failed")

	// Test 16
	number = 1099511627775
	bytes = EncodeUint(number)
	expected = []byte{5, 255, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Uint test 16 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 16 decoding failed")

	// Test 17
	number = 1099511627776
	bytes = EncodeUint(number)
	expected = []byte{6, 1, 0, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Uint test 17 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 17 decoding failed")

	// Test 18
	number = 213688030935051
	bytes = EncodeUint(number)
	expected = []byte{6, 194, 89, 31, 45, 56, 11}
	testCompareByteArrays(t, bytes, expected, "Uint test 18 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 18 decoding failed")

	// Test 19
	number = 281474976710655
	bytes = EncodeUint(number)
	expected = []byte{6, 255, 255, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Uint test 19 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 19 decoding failed")

	// Test 20
	number = 281474976710656
	bytes = EncodeUint(number)
	expected = []byte{7, 1, 0, 0, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Uint test 20 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 20 decoding failed")

	// Test 21
	number = 56491282019046242
	bytes = EncodeUint(number)
	expected = []byte{7, 200, 178, 133, 141, 166, 211, 98}
	testCompareByteArrays(t, bytes, expected, "Uint test 21 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 21 decoding failed")

	// Test 22
	number = 72057594037927935
	bytes = EncodeUint(number)
	expected = []byte{7, 255, 255, 255, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Uint test 22 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 22 decoding failed")

	// Test 23
	number = 72057594037927936
	bytes = EncodeUint(number)
	expected = []byte{8, 1, 0, 0, 0, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Uint test 23 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 23 decoding failed")

	// Test 24
	number = 13247848946842148119
	bytes = EncodeUint(number)
	expected = []byte{8, 183, 217, 208, 109, 82, 143, 29, 23}
	testCompareByteArrays(t, bytes, expected, "Uint test 24 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test 24 decoding failed")

	// Test 25
	number = 18446744073709551615
	bytes = EncodeUint(number)
	expected = []byte{8, 255, 255, 255, 255, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Uint test 25 encoding failed")
	testCompareUint64s(t, DecodeUint(bytes), number, "Uint test decoding failed")

}

func TestEncodeInt(t *testing.T) {
	var number int64

	// Test 1
	number = 0
	bytes := EncodeInt(number)
	expected := []byte{0}
	testCompareByteArrays(t, bytes, expected, "Int test 1 encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 1 decoding failed")

	// Test 2P
	number = 1
	bytes = EncodeInt(number)
	expected = []byte{1, 1}
	testCompareByteArrays(t, bytes, expected, "Int test 2P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 2P decoding failed")

	// Test 2N
	number = -1
	bytes = EncodeInt(number)
	expected = []byte{129, 1}
	testCompareByteArrays(t, bytes, expected, "Int test 2N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 2N decoding failed")

	// Test 3P
	number = 47
	bytes = EncodeInt(number)
	expected = []byte{1, 47}
	testCompareByteArrays(t, bytes, expected, "Int test 3P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 3P decoding failed")

	// Test 3N
	number = -47
	bytes = EncodeInt(number)
	expected = []byte{129, 47}
	testCompareByteArrays(t, bytes, expected, "Int test 3N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 3N decoding failed")

	// Test 4P
	number = 255
	bytes = EncodeInt(number)
	expected = []byte{1, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 4P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 4P decoding failed")

	// Test 4N
	number = -255
	bytes = EncodeInt(number)
	expected = []byte{129, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 4N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 4N decoding failed")

	// Test 5P
	number = 256
	bytes = EncodeInt(number)
	expected = []byte{2, 1, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 5P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 5P decoding failed")

	// Test 5N
	number = -256
	bytes = EncodeInt(number)
	expected = []byte{130, 1, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 5N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 5N decoding failed")

	// Test 6P
	number = 58295
	bytes = EncodeInt(number)
	expected = []byte{2, 227, 183}
	testCompareByteArrays(t, bytes, expected, "Int test 6P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 6P decoding failed")

	// Test 6N
	number = -58295
	bytes = EncodeInt(number)
	expected = []byte{130, 227, 183}
	testCompareByteArrays(t, bytes, expected, "Int test 6N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 6N decoding failed")

	// Test 7P
	number = 65535
	bytes = EncodeInt(number)
	expected = []byte{2, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 7P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 7P decoding failed")

	// Test 7N
	number = -65535
	bytes = EncodeInt(number)
	expected = []byte{130, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 7N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 7N decoding failed")

	// Test 8P
	number = 65536
	bytes = EncodeInt(number)
	expected = []byte{3, 1, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 8P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 8P decoding failed")

	// Test 8N
	number = -65536
	bytes = EncodeInt(number)
	expected = []byte{131, 1, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 8N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 8N decoding failed")

	// Test 9P
	number = 12543843
	bytes = EncodeInt(number)
	expected = []byte{3, 191, 103, 99}
	testCompareByteArrays(t, bytes, expected, "Int test 9P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 9P decoding failed")

	// Test 9N
	number = -12543843
	bytes = EncodeInt(number)
	expected = []byte{131, 191, 103, 99}
	testCompareByteArrays(t, bytes, expected, "Int test 9N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 9N decoding failed")

	// Test 10P
	number = 16777215
	bytes = EncodeInt(number)
	expected = []byte{3, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 10P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 10P decoding failed")

	// Test 10N
	number = -16777215
	bytes = EncodeInt(number)
	expected = []byte{131, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 10N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 10N decoding failed")

	// Test 11P
	number = 16777216
	bytes = EncodeInt(number)
	expected = []byte{4, 1, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 11P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 11P decoding failed")

	// Test 11N
	number = -16777216
	bytes = EncodeInt(number)
	expected = []byte{132, 1, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 11N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 11N decoding failed")

	// Test 12P
	number = 1698780716
	bytes = EncodeInt(number)
	expected = []byte{4, 101, 65, 86, 44}
	testCompareByteArrays(t, bytes, expected, "Int test 12P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 12P decoding failed")

	// Test 12N
	number = -1698780716
	bytes = EncodeInt(number)
	expected = []byte{132, 101, 65, 86, 44}
	testCompareByteArrays(t, bytes, expected, "Int test 12N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 12N decoding failed")

	// Test 13P
	number = 4294967295
	bytes = EncodeInt(number)
	expected = []byte{4, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 13P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 13P decoding failed")

	// Test 13N
	number = -4294967295
	bytes = EncodeInt(number)
	expected = []byte{132, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 13N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 13N decoding failed")

	// Test 14P
	number = 4294967296
	bytes = EncodeInt(number)
	expected = []byte{5, 1, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 14P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 14P decoding failed")

	// Test 14N
	number = -4294967296
	bytes = EncodeInt(number)
	expected = []byte{133, 1, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 14N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 14N decoding failed")

	// Test 15P
	number = 1062657006408
	bytes = EncodeInt(number)
	expected = []byte{5, 247, 107, 75, 27, 72}
	testCompareByteArrays(t, bytes, expected, "Int test 15P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 15P decoding failed")

	// Test 15N
	number = -1062657006408
	bytes = EncodeInt(number)
	expected = []byte{133, 247, 107, 75, 27, 72}
	testCompareByteArrays(t, bytes, expected, "Int test 15N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 15N decoding failed")

	// Test 16P
	number = 1099511627775
	bytes = EncodeInt(number)
	expected = []byte{5, 255, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 16P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 16P decoding failed")

	// Test 16N
	number = -1099511627775
	bytes = EncodeInt(number)
	expected = []byte{133, 255, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 16N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 16N decoding failed")

	// Test 17P
	number = 1099511627776
	bytes = EncodeInt(number)
	expected = []byte{6, 1, 0, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 17P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 17P decoding failed")

	// Test 17N
	number = -1099511627776
	bytes = EncodeInt(number)
	expected = []byte{134, 1, 0, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 17N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 17N decoding failed")

	// Test 18P
	number = 213688030935051
	bytes = EncodeInt(number)
	expected = []byte{6, 194, 89, 31, 45, 56, 11}
	testCompareByteArrays(t, bytes, expected, "Int test 18P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 18P decoding failed")

	// Test 18N
	number = -213688030935051
	bytes = EncodeInt(number)
	expected = []byte{134, 194, 89, 31, 45, 56, 11}
	testCompareByteArrays(t, bytes, expected, "Int test 18N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 18N decoding failed")

	// Test 19P
	number = 281474976710655
	bytes = EncodeInt(number)
	expected = []byte{6, 255, 255, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 19P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 19P decoding failed")

	// Test 19N
	number = -281474976710655
	bytes = EncodeInt(number)
	expected = []byte{134, 255, 255, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 19N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 19N decoding failed")

	// Test 20P
	number = 281474976710656
	bytes = EncodeInt(number)
	expected = []byte{7, 1, 0, 0, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 20P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 20P decoding failed")

	// Test 20N
	number = -281474976710656
	bytes = EncodeInt(number)
	expected = []byte{135, 1, 0, 0, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 20N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 20N decoding failed")

	// Test 21P
	number = 56491282019046242
	bytes = EncodeInt(number)
	expected = []byte{7, 200, 178, 133, 141, 166, 211, 98}
	testCompareByteArrays(t, bytes, expected, "Int test 21P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 21P decoding failed")

	// Test 21N
	number = -56491282019046242
	bytes = EncodeInt(number)
	expected = []byte{135, 200, 178, 133, 141, 166, 211, 98}
	testCompareByteArrays(t, bytes, expected, "Int test 21N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 21N decoding failed")

	// Test 22P
	number = 72057594037927935
	bytes = EncodeInt(number)
	expected = []byte{7, 255, 255, 255, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 22P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 22P decoding failed")

	// Test 22N
	number = -72057594037927935
	bytes = EncodeInt(number)
	expected = []byte{135, 255, 255, 255, 255, 255, 255, 255}
	testCompareByteArrays(t, bytes, expected, "Int test 22N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 22N decoding failed")

	// Test 23P
	number = 72057594037927936
	bytes = EncodeInt(number)
	expected = []byte{8, 1, 0, 0, 0, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 23P encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 23P decoding failed")

	// Test 23N
	number = -72057594037927936
	bytes = EncodeInt(number)
	expected = []byte{136, 1, 0, 0, 0, 0, 0, 0, 0}
	testCompareByteArrays(t, bytes, expected, "Int test 23N encoding failed")
	testCompareInt64s(t, DecodeInt(bytes), number, "Int test 23N decoding failed")

}

func TestMakingBlocks(t *testing.T) {
	var ii int
	ii = 5
	block := MakeBlockInt(ii)
	testCompareByteArrays(t, block, []byte{1, 2, 1, 5}, "MakeBlockInt test 1 failed")

	// Test large integer
	ii = 56491282019046242
	block = MakeBlockInt(ii)
	testCompareByteArrays(t, block, []byte{1, 8, 7, 200, 178, 133, 141, 166, 211, 98}, "MakeBlockInt test 2 failed")

	// Test large negative integer
	ii = -65942128100962442
	block = MakeBlockInt(ii)
	testCompareByteArrays(t, block, []byte{1, 8, 135, 234, 70, 4, 33, 48, 240, 138}, "MakeBlockInt test 3 failed")

	// Test string
	var ss string
	ss = "Hello World."
	block = MakeBlockString(ss)
	testCompareByteArrays(t, block, []byte{1, 12, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 46}, "MakeBlockString test failed")

	// Test float
	var ff float64
	ff = 1.4645918875631094
	block = MakeBlockFloat(ff)
	testCompareByteArrays(t, block, []byte{1, 18, 49, 46, 52, 54, 52, 53, 57, 49, 56, 56, 55, 53, 54, 51, 49, 48, 57, 52}, "MakeBlockFloat test failed")

	// Test a string longer than 255 characters
	ss = "Go is an open source programming language that makes it easy to build simple, reliable, and efficient software. It is a general-purpose language designed with systems programming in mind. It is strongly typed and garbage-collected and has explicit support for concurrent programming. Programs are constructed from packages, whose properties allow efficient management of dependencies. The grammar is compact and regular, allowing for easy analysis by automatic tools such as integrated development environments."
	block = MakeBlockString(ss)
	ls := len(ss)
	if block[0] != 2 {
		t.Error("block[0] is not 2")
	}
	if ((int(block[1]) * 256) + int(block[2])) != ls {
		t.Error("block[1] and black[2] do not contain the length of the string")
	}
	final := MakeBlockByteArray(block)
	testCompareByteArrays(t, final, []byte{2, 2, 2, 2, 1, 255, 71, 111, 32, 105, 115, 32, 97, 110, 32, 111, 112, 101, 110, 32, 115, 111, 117, 114, 99, 101, 32, 112, 114, 111, 103, 114, 97, 109, 109, 105, 110, 103, 32, 108, 97, 110, 103, 117, 97, 103, 101, 32, 116, 104, 97, 116, 32, 109, 97, 107, 101, 115, 32, 105, 116, 32, 101, 97, 115, 121, 32, 116, 111, 32, 98, 117, 105, 108, 100, 32, 115, 105, 109, 112, 108, 101, 44, 32, 114, 101, 108, 105, 97, 98, 108, 101, 44, 32, 97, 110, 100, 32, 101, 102, 102, 105, 99, 105, 101, 110, 116, 32, 115, 111, 102, 116, 119, 97, 114, 101, 46, 32, 73, 116, 32, 105, 115, 32, 97, 32, 103, 101, 110, 101, 114, 97, 108, 45, 112, 117, 114, 112, 111, 115, 101, 32, 108, 97, 110, 103, 117, 97, 103, 101, 32, 100, 101, 115, 105, 103, 110, 101, 100, 32, 119, 105, 116, 104, 32, 115, 121, 115, 116, 101, 109, 115, 32, 112, 114, 111, 103, 114, 97, 109, 109, 105, 110, 103, 32, 105, 110, 32, 109, 105, 110, 100, 46, 32, 73, 116, 32, 105, 115, 32, 115, 116, 114, 111, 110, 103, 108, 121, 32, 116, 121, 112, 101, 100, 32, 97, 110, 100, 32, 103, 97, 114, 98, 97, 103, 101, 45, 99, 111, 108, 108, 101, 99, 116, 101, 100, 32, 97, 110, 100, 32, 104, 97, 115, 32, 101, 120, 112, 108, 105, 99, 105, 116, 32, 115, 117, 112, 112, 111, 114, 116, 32, 102, 111, 114, 32, 99, 111, 110, 99, 117, 114, 114, 101, 110, 116, 32, 112, 114, 111, 103, 114, 97, 109, 109, 105, 110, 103, 46, 32, 80, 114, 111, 103, 114, 97, 109, 115, 32, 97, 114, 101, 32, 99, 111, 110, 115, 116, 114, 117, 99, 116, 101, 100, 32, 102, 114, 111, 109, 32, 112, 97, 99, 107, 97, 103, 101, 115, 44, 32, 119, 104, 111, 115, 101, 32, 112, 114, 111, 112, 101, 114, 116, 105, 101, 115, 32, 97, 108, 108, 111, 119, 32, 101, 102, 102, 105, 99, 105, 101, 110, 116, 32, 109, 97, 110, 97, 103, 101, 109, 101, 110, 116, 32, 111, 102, 32, 100, 101, 112, 101, 110, 100, 101, 110, 99, 105, 101, 115, 46, 32, 84, 104, 101, 32, 103, 114, 97, 109, 109, 97, 114, 32, 105, 115, 32, 99, 111, 109, 112, 97, 99, 116, 32, 97, 110, 100, 32, 114, 101, 103, 117, 108, 97, 114, 44, 32, 97, 108, 108, 111, 119, 105, 110, 103, 32, 102, 111, 114, 32, 101, 97, 115, 121, 32, 97, 110, 97, 108, 121, 115, 105, 115, 32, 98, 121, 32, 97, 117, 116, 111, 109, 97, 116, 105, 99, 32, 116, 111, 111, 108, 115, 32, 115, 117, 99, 104, 32, 97, 115, 32, 105, 110, 116, 101, 103, 114, 97, 116, 101, 100, 32, 100, 101, 118, 101, 108, 111, 112, 109, 101, 110, 116, 32, 101, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 115, 46}, "Test of MakeBlockString with string > 255 chars and MakeBlockByteArray failed")
}

func testDecode(t *testing.T, bitsOnTheWire []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	copy(iv, bitsOnTheWire)
	key, _ := hex.DecodeString("a9672b783092f3f3049a5764d1c906f4d96e4914cf6b549d94280ee0f0814d56")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Error(err)
	}
	stream := cipher.NewOFB(block, iv)
	llbyte := make([]byte, 5) // EEEE + length byte
	position := aes.BlockSize
	stream.XORKeyStream(llbyte, bitsOnTheWire[position:position+5])
	position += 5
	if llbyte[0] != 'E' {
		return nil
	}
	if llbyte[1] != 'E' {
		return nil
	}
	if llbyte[2] != 'E' {
		return nil
	}
	if llbyte[3] != 'E' {
		return nil
	}
	lli := int(llbyte[4])
	if lli > 8 {
		t.Error("llbyte is > 8")
	}
	lbytes := make([]byte, lli)
	stream.XORKeyStream(lbytes, bitsOnTheWire[position:position+lli])
	position += lli
	// ok, we have all the length bytes -- now we have to decode
	llTemp := make([]byte, lli+1)
	llTemp[0] = llbyte[4]
	copy(llTemp[1:], lbytes)
	messageLen := int(DecodeUint(llTemp))
	//
	// here's where in a real receiver, we'd allocate messageLen bytes to receive the message (+ extra for the signature)
	plaintext := make([]byte, messageLen)
	stream.XORKeyStream(plaintext, bitsOnTheWire[position:position+messageLen])
	position += messageLen
	//
	// check the signature
	hmacKey, _ := hex.DecodeString("84982f4a55885d7dfff30d72dcf74ad3b309683d4ac89935fddeca40efdc7ce4")
	hasher := hmac.New(sha256.New, hmacKey)
	hasher.Write(bitsOnTheWire[aes.BlockSize:position])
	expectedMAC := hasher.Sum(nil)
	match := hmac.Equal(bitsOnTheWire[position:], expectedMAC)
	if match {
		return plaintext
	}
	return nil
}

func TestMakeAndExtractBlock(t *testing.T) {
	block1 := MakeBlockString("Hello")
	block2 := MakeBlockString("World")
	block3 := MakeBlockInt(99999999)
	block4 := MakeBlockFloat(3.1415936536) // note typo
	message := append(block1, block2...)
	message = append(message, block3...)
	message = append(message, block4...)
	offset := 0
	start, end := ExtractBlock(message, offset)
	if start != 2 {
		t.Error("ExtractBlock returned invalid start value")
	}
	if end != 7 {
		t.Error("ExtractBlock returned invalid end value")
	}
	stg1, offset := getBlockString(message, offset)
	if stg1 != "Hello" {
		t.Error("String extract test 1 failed")
	}
	if offset != 7 {
		t.Error("String extract returned incorrect offset")
	}
	stg2, offset := getBlockString(message, offset)
	if stg2 != "World" {
		t.Error("String extract test 2 failed")
	}
	if offset != 14 {
		t.Error("String extract test 2 offset test failed")
	}
	itv3, offset := GetBlockInt(message, offset)
	if itv3 != 99999999 {
		t.Error("Int extract test 1 failed")
	}
	if offset != 21 {
		t.Error("Int extract offset test failed")
	}
	flt4, offset, err := getBlockFloat(message, offset)
	if err != nil {
		t.Error("Floating point extract decode test 1 failed")
	}
	if flt4 != 3.1415936536 {
		t.Error("Floating point extract test 1 failed")
	}
	if offset != 35 {
		t.Error("Floating point extract offset test 1 failed")
	}
}

func TestMarshalling(t *testing.T) {
	var rpc XWRPC
	rpc.StartDB("Func1", 0, 2)
	rpc.StartTable("Table1", 5, 3)

	rpc.AddColumn("Param1", ColInt)
	rpc.AddColumn("Param2", ColUint)
	rpc.AddColumn("Param3", ColBool)
	rpc.AddColumn("Param4", ColFloat)
	rpc.AddColumn("Param5", ColString)
	rpc.AddColumn("Param6", ColByteArray)

	rpc.StartRow()
	rpc.AddRowColumnInt(int64(-555))
	rpc.AddRowColumnUint(uint64(777))
	rpc.AddRowColumnBool(false)
	rpc.AddRowColumnFloat(897087.9783408)
	rpc.AddRowColumnString("This is a string.")
	rpc.AddRowColumnByteArray([]byte("TestBytes"))

	rpc.StartRow()
	rpc.AddRowColumnInt(int64(33))
	rpc.AddRowColumnUint(uint64(7771))
	rpc.AddRowColumnBool(true)
	rpc.AddRowColumnFloat(3.5)
	rpc.AddRowColumnString("This is actually a string.")
	rpc.AddRowColumnByteArray([]byte("TestBytes1602"))

	rpc.StartRow()
	rpc.AddRowColumnInt(int64(-515))
	rpc.AddRowColumnUint(uint64(787))
	rpc.AddRowColumnBool(true)
	rpc.AddRowColumnFloat(3.333111333)
	rpc.AddRowColumnString("This is really a string.")
	rpc.AddRowColumnByteArray([]byte("Bytes1609"))

	rpc.StartTable("Table2", 2, 2)
	rpc.AddColumn("T2P1", ColInt)
	rpc.AddColumn("T2P2", ColString)

	rpc.StartRow()
	rpc.AddRowColumnInt(int64(111))
	rpc.AddRowColumnString("Tbl2String1130")

	rpc.StartRow()
	rpc.AddRowColumnInt(int64(222))
	rpc.AddRowColumnString("Tbl2Str20190119")

	// rpc.SendDB(&netConnection)

	// netConnection.Close()

	err := rpc.MarshallDB()
	if err != nil {
		t.Error("Marshaller threw an error.")
	}
	var callback XWRPC
	callback.message = rpc.message // hack for testing
	callback.UnmarshallDB()

	numTables := callback.GetNumTables()
	if numTables != 2 {
		t.Error("Number of tables is not 2")
	}
	for tblNum := 0; tblNum < numTables; tblNum++ {
		numCols := callback.GetNumCols(tblNum)
		switch tblNum {
		case 0:
			if numCols != 6 {
				t.Error("Number of columns on table 0 is not 6")
			}
		case 1:
			if numCols != 2 {
				t.Error("Number of columns on table 1 is not 2")
			}
		default:
			t.Error("Table count exceeds 2")
		}

		for colNum := 0; colNum < numCols; colNum++ {
			colName := callback.GetColName(tblNum, colNum)
			colType := callback.GetColType(tblNum, colNum)
			// fmt.Println("tblNum", tblNum, "colNum", colNum)
			// fmt.Println("colType", colType)
			switch tblNum {
			case 0:
				switch colNum {
				case 0:
					if colName != "Param1" {
						t.Error("colName is not Param1")
					}
					if colType != ColInt {
						t.Error("colType is not ColInt")
					}
				case 1:
					if colName != "Param2" {
						t.Error("colName is not Param2")
					}
					if colType != ColUint {
						t.Error("colType is not ColUint")
					}
				case 2:
					if colName != "Param3" {
						t.Error("colName is not Param3")
					}
					if colType != ColBool {
						t.Error("colType is not ColBool")
					}
				case 3:
					if colName != "Param4" {
						t.Error("colName is not Param4")
					}
					if colType != ColFloat {
						t.Error("colType is not ColFloat")
					}
				case 4:
					if colName != "Param5" {
						t.Error("colName is not Param5")
					}
					if colType != ColString {
						t.Error("colType is not ColString")
					}
				case 5:
					if colName != "Param6" {
						t.Error("colName is not Param6")
					}
					if colType != ColByteArray {
						t.Error("colType is not ColByteArray")
					}
				default:
					t.Error("Column number is invalid on table 0")
				}
			case 1:
				switch colNum {
				case 0:
					if colName != "T2P1" {
						t.Error("colName is not T2P1")
					}
					if colType != ColInt {
						t.Error("colType is not ColInt")
					}
				case 1:
					if colName != "T2P2" {
						t.Error("colName is not T2P2")
					}
					if colType != ColString {
						t.Error("colType is not ColString")
					}
				default:
					t.Error("Column number is invalid on table 1")
				}
			default:
				t.Error("table number is invalid")
			}
		}
		numRows := callback.GetNumRows(tblNum)
		for rowNum := 0; rowNum < numRows; rowNum++ {
			for colNum := 0; colNum < numCols; colNum++ {
				colType := callback.GetColType(tblNum, colNum)
				switch colType {
				case ColInt:
					ival, err := callback.GetInt(tblNum, rowNum, colNum)
					if err != nil {
						t.Error("Int extract failed in int column")
					}
					// fmt.Println("tblNum", tblNum, "rowNum", rowNum, "colNum", colNum, "ival", ival)
					switch tblNum {
					case 0:
						switch rowNum {
						case 0:
							switch colNum {
							case 0:
								if ival != -555 {
									t.Error("Int value is not -555")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 0")
							}
						case 1:
							switch colNum {
							case 0:
								if ival != 33 {
									t.Error("ival is not 33")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 1 on ColInt")
							}
						case 2:
							switch colNum {
							case 0:
								if ival != -515 {
									t.Error("ival is not -515")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 2 on colInt")
							}
						default:
							t.Error("Row number is invalid on values on ColInt")
						}
					case 1:
						switch rowNum {
						case 0:
							switch colNum {
							case 0:
								if ival != 111 {
									t.Error("ival is not 111")
								}
							default:
								t.Error("Column number is invalid on values on table 1 row 1 on colInt")
							}
						case 1:
							switch colNum {
							case 0:
								if ival != 222 {
									t.Error("ival is not 222")
								}
							}
						default:
							t.Error("Row number is invalid on values on table 1")
						}
					default:
						t.Error("Table number is invalid on colInt")
					}
				case ColUint:
					uval, err := callback.GetUint(tblNum, rowNum, colNum)
					if err != nil {
						t.Error("Unsigned int extract in column failed")
					}
					// fmt.Println("tblNum", tblNum, "rowNum", rowNum, "colNum", colNum, "uval", uval)
					switch tblNum {
					case 0:
						switch rowNum {
						case 0:
							switch colNum {
							case 1:
								if uval != 777 {
									t.Error("unsigned int val is not 777")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 0 on ColUint")
							}
						case 1:
							switch colNum {
							case 1:
								if uval != 7771 {
									t.Error("Unsigned int values is not 7771")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 1 on ColUint")
							}
						case 2:
							switch colNum {
							case 1:
								if uval != 787 {
									t.Error("Unsigned int value is not 787")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 2 on ColUint")
							}
						default:
							t.Error("Row number is invalid on values on table 0 on ColUint")
						}
					default:
						t.Error("Table number is invalid on ColUint")
					}
				case ColBool:
					bval, err := callback.GetBool(tblNum, rowNum, colNum)
					if err != nil {
						t.Error("bool extract in column failed")
					}
					// fmt.Println("tblNum", tblNum, "rowNum", rowNum, "colNum", colNum, "bval", bval)
					switch tblNum {
					case 0:
						switch rowNum {
						case 0:
							switch colNum {
							case 2:
								if bval != false {
									t.Error("bool value is not false")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 0 on ColBool")
							}
						case 1:
							switch colNum {
							case 2:
								if bval != true {
									t.Error("bool value is not true")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 1 on ColBool")
							}
						case 2:
							switch colNum {
							case 2:
								if bval != true {
									t.Error("bool value is not 787")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 2 on ColBool")
							}
						default:
							t.Error("Row number is invalid on values on table 0 on ColBool")
						}
					default:
						t.Error("Table number is invalid on ColBool")
					}
				case ColFloat:
					fval, err := callback.GetFloat(tblNum, rowNum, colNum)
					if err != nil {
						t.Error("extract of GetFloat failed on float column")
					}
					// fmt.Println("tblNum", tblNum, "rowNum", rowNum, "colNum", colNum, "fval", fval)
					switch tblNum {
					case 0:
						switch rowNum {
						case 0:
							switch colNum {
							case 3:
								if fval != 897087.9783408 {
									t.Error("fval is not 897087.9783408")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 0 on ColFloat")
							}
						case 1:
							switch colNum {
							case 3:
								if fval != 3.5 {
									t.Error("float value is not 3.5")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 1 on ColFloat")
							}
						case 2:
							switch colNum {
							case 3:
								if fval != 3.333111333 {
									t.Error("float value is not 3.333111333")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 2 on ColFloat")
							}
						default:
							t.Error("Row number is invalid on values on table 0 on ColFloat")
						}
					default:
						t.Error("Table number is invalid on values on ColFloat")
					}
				case ColString:
					sval, err := callback.GetString(tblNum, rowNum, colNum)
					if err != nil {
						t.Error("Extract GetString for column failed")
					}
					// fmt.Println("tblNum", tblNum, "rowNum", rowNum, "colNum", colNum, "sval", sval)
					switch tblNum {
					case 0:
						switch rowNum {
						case 0:
							switch colNum {
							case 4:
								if sval != "This is a string." {
									t.Error("sval is not this is a string")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 0 on ColString")
							}
						case 1:
							switch colNum {
							case 4:
								if sval != "This is actually a string." {
									t.Error("sval is not this is actually a string")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 1 on ColString")
							}
						case 2:
							switch colNum {
							case 4:
								if sval != "This is really a string." {
									t.Error("sval is not this is really a string")
								}
							default:
								t.Error("Column number is invalid on values on table 0 row 2 on ColString")
							}
						default:
							t.Error("Row number is invalid on values on table 0 on ColString")
						}
					case 1:
						switch rowNum {
						case 0:
							switch colNum {
							case 1:
								if sval != "Tbl2String1130" {
									t.Error("sval is not Tbl2String1130")
								}
							default:
								t.Error("Column number is invalid on values on table 1 row 0 on ColString")
							}
						case 1:
							switch colNum {
							case 1:
								if sval != "Tbl2Str20190119" {
									t.Error("sval is not Tbl2Str20190119")
								}
							default:
								t.Error("Column number is invalid on values on table 1 row 1 on ColString")
							}
						default:
							t.Error("Row number is invalid on values on table 1 on ColString")
						}
					default:
						t.Error("Table number is invalid on values on ColString")
					}
				case ColByteArray:
					bval, err := callback.GetByteArray(tblNum, rowNum, colNum)
					if err != nil {
						t.Error("GetByteArray extraction in column failed")
					}
					// fmt.Println("tblNum", tblNum, "rowNum", rowNum, "colNum", colNum, "bval", bval)
					switch tblNum {
					case 0:
						switch rowNum {
						case 0:
							switch colNum {
							case 5:
								testCompareByteArrays(t, bval, []byte{84, 101, 115, 116, 66, 121, 116, 101, 115}, "byte array table 0 row 0 colum 4 is invalid")
							default:
								t.Error("Column number is invalid on values on table 0 row 0 on ColByteArray")
							}
						case 1:
							switch colNum {
							case 5:
								testCompareByteArrays(t, bval, []byte{84, 101, 115, 116, 66, 121, 116, 101, 115, 49, 54, 48, 50}, "byte array table 0 row 1 column 4 invalid")
							default:
								t.Error("Column number is invalid on values on table 0 row 1 on ColByteArray")
							}
						case 2:
							switch colNum {
							case 5:
								testCompareByteArrays(t, bval, []byte{66, 121, 116, 101, 115, 49, 54, 48, 57}, "byte array table 0 row 1 column 4 invalid")
							default:
								t.Error("Column number is invalid on values on table 0 row 2 on ColByteArray")
							}
						default:
							t.Error("Row number is invalid on values on table 0 on ColByteArray")
						}
					default:
						t.Error("Table number is invalid on values on ColByteArray")
					}
				default:
					t.Error("Unrecognized column type returned")
				}
			}
		}
	}

	// Final step is to test the encryption and decryption

	symmetricKey, _ := hex.DecodeString("a9672b783092f3f3049a5764d1c906f4d96e4914cf6b549d94280ee0f0814d56")
	hmacKey, _ := hex.DecodeString("84982f4a55885d7dfff30d72dcf74ad3b309683d4ac89935fddeca40efdc7ce4")

	var wnetcon WNetConnection
	wnetcon.SetDest("localhost", 4000)
	wnetcon.SetKeys(symmetricKey, hmacKey)
	// wnetcon.Open() // we don't actually open a connection in the automated tests

	wnetcon.EnvelopMessage(rpc.message, true)
	msgBack, err := wnetcon.DevelopMessage()
	if err != nil {
		t.Error("DevelopMessage failed")
	}

	testCompareByteArrays(t, rpc.message, msgBack, "DevelopMessage failed to return the message we started with")
}
