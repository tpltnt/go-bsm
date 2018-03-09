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
