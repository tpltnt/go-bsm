// test parsing of BSM files
package main

import (
	"bytes"
	"strconv"
	"testing"
)

func Test_bytesToUint32(t *testing.T) {
	testdata := map[uint32][]byte{
		0:        []byte{0x00},
		1:        []byte{0x01},
		2:        []byte{0x00, 0x02},
		3:        []byte{0x00, 0x00, 0x00, 0x03},
		256:      []byte{0x01, 0x00},
		257:      []byte{0x01, 0x01},
		258:      []byte{0x00, 0x01, 0x02},
		65536:    []byte{0x00, 0x01, 0x00, 0x00},
		16777218: []byte{0x01, 0x00, 0x00, 0x02},
	}
	for k, v := range testdata {
		number, err := bytesToUint32(v)
		if err != nil {
			t.Error(err.Error())
		}
		if number != k {
			t.Error("could not decode " + strconv.Itoa(int(k)) + " correctly, got " + strconv.Itoa(int(number)))
		}
	}
	_, err := bytesToUint32([]byte{0xff, 0x01, 0xac, 0xb4, 0x2c})
	if err == nil {
		t.Error("did not catch overflow")
	}
}

func TestRecordsFromFile(t *testing.T) {
	data := []byte{0x00}
	err := RecordsFromFile(bytes.NewBuffer(data))
	if err == nil {
		t.Error("one byte record should yield an error")
	}
}

// fixed sized tokens
func Test_determineTokenSize_fixed(t *testing.T) {
	testData := map[byte]int{
		0x13: 7,  // trailer token
		0x14: 19, // 32 bit header token
		0x24: 37, // 32 bit subject token
		0x27: 6,  // 32 bit return token
		0x72: 10, // 64 bit return token
		0x74: 27, // 64 bit header token
		0x75: 41, // 64 bit subject token
	}
	for tokenID, count := range testData {
		dcount, _, err := determineTokenSize([]byte{tokenID})
		if err != nil {
			t.Error(err)
		}
		if dcount != count {
			t.Error("token size does not match expectation of token ID")
		}
	}
}

func Test_determineTokenSize_file_token(t *testing.T) {
	testData := []byte{}

	// missing token ID
	_, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 1 {
		t.Error("expected 1 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}

	// correct token ID, bot no more
	testData = []byte{0x11}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 10 {
		t.Error("expected 10 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}

	// correct token (in terms of size)
	testData = []byte{0x11, // token ID
		0x00, 0x01, 0x02, 0x03, // seconds
		0x04, 0x05, 0x06, 0x07, // microseconds
		0x23, 0xf8, // file name length
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	if size != (11 + 9208 + 1) { // 11 inital bytes + file name length (from hex) + NUL
		t.Error("wrong size: expected " + strconv.Itoa(11+9208+1) + ", got " + strconv.Itoa(size))
	}

}

func TestParseHeaderToken32bit(t *testing.T) {
	data := []byte{0x14, // token ID \
		0x00, 0x00, 0x00, 0x38, // record byte number \
		0x0b, 0xaf, // version number
		0xc8, 0x00, // event type
		0x00, 0x5a, // event sub-type / modifier
		0x9a, 0xc2, 0xe6, 0x00, // seconds
		0x00, 0x03, 0x01, 0x28, // nanoseconds
	}
	token, err := ParseHeaderToken32bit(data)
	if err != nil {
		t.Error(err.Error())
	}
	if token.TokenID != 0x14 {
		t.Error("wrong token ID")
	}
	if token.RecordByteCount != 56 {
		t.Error("wrong record byte count, got " + strconv.Itoa(int(token.RecordByteCount)))
	}
	if token.VersionNumber != 2991 {
		t.Error("wrong version number")
	}
	if token.EventType != 51200 {
		t.Error("wrong event type")
	}
	if token.EventModifier != 90 {
		t.Error("wrong event modifier")
	}
	if token.Seconds != 2596464128 {
		t.Error("wrong number of seconds")
	}
	if token.NanoSeconds != 196904 {
		t.Error("wrong number of nanoseconds")
	}

}
