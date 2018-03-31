// test parsing of BSM files
package main

import (
	"bytes"
	"os"
	"strconv"
	"strings"
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

func TestTokenFromByteInput(t *testing.T) {
	data := []byte{0x00}
	_, err := TokenFromByteInput(bytes.NewBuffer(data))
	if err == nil {
		t.Error("one byte record should yield an error")
	}
	if !strings.Contains(err.Error(), "can't determine the size of the given token (type)") {
		t.Error("unexpected error message:", err.Error())
	}
	// iport token as minimal test case
	data = []byte{0x2c, 0x23, 0x42}
	token, err := TokenFromByteInput(bytes.NewBuffer(data))
	if err != nil {
		t.Error(err)
	}
	switch v := token.(type) {
	case IPortToken:
		if v.PortNumber != 9026 {
			t.Error("wrong port number in IPortToken")
		}
	default:
		t.Error("expected IPortToken, but got", v)
	}
}

// fixed sized tokens
func Test_determineTokenSize_fixed(t *testing.T) {
	testData := map[byte]int{
		0x13: 7,  // trailer token
		0x14: 18, // 32 bit header token
		0x22: 6,  // System V IPC token
		0x24: 37, // 32 bit subject token
		0x26: 37, // 32 bit process token
		0x27: 6,  // 32 bit return token
		0x2a: 5,  // in_addr token
		0x2b: 21, // ip token
		0x2c: 3,  // iport token
		0x2e: 9,  // socket token
		0x2f: 5,  // seq token
		0x32: 29, // System V IPV permission token
		0x3e: 29, // 32 bit attribute token
		0x52: 9,  // exit token
		0x72: 10, // 64 bit return token
		0x73: 33, // 64 bit attribute token
		0x74: 26, // 64 bit header token
		0x75: 41, // 64 bit subject token
		0x77: 45, // 64 bit process token
		0x7e: 18, // expanded in_addr token
		0x80: 9,  // inet32 socket token
		0x81: 21, // inet128 socket token
		0x82: 9,  // FreeBSD socket token
	}
	for tokenID, count := range testData {
		dcount, _, err := determineTokenSize([]byte{tokenID})
		if err != nil {
			t.Error(err)
		}
		if dcount != count {
			t.Errorf("token size (%d) does not match expectation of token ID 0x%x (%d)", dcount, tokenID, count)
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

func Test_determineTokenSize_expanded_32bit_subject_token(t *testing.T) {
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
	testData = []byte{0x7a}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 36 {
		t.Error("expected 36 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}

	// correct token (in terms of size)
	testData = []byte{0x7a, // token ID
		0x00, 0x01, 0x02, 0x03, // audit user ID
		0x00, 0x01, 0x02, 0x03, // effective user ID
		0x00, 0x01, 0x02, 0x03, // effective group ID
		0x00, 0x01, 0x02, 0x03, // real user ID
		0x00, 0x01, 0x02, 0x03, // real group ID
		0x00, 0x01, 0x02, 0x03, // process ID
		0x00, 0x01, 0x02, 0x03, // audit session ID
		0x00, 0x01, 0x02, 0x03, // terminal port ID
		0x00, 0x00, 0x00, 0x00, // length of address
		0x00, 0x01, 0x02, 0x03, // IPv4
	}
	size, more, err := determineTokenSize(testData)
	if err == nil {
		t.Error("expected an error on invalid address length")
	}
	testData[36] = 4 // IPv4
	size, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 41
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}

}

func Test_determineTokenSize_expanded_64bit_subject_token(t *testing.T) {
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
	testData = []byte{0x7c}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 37
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}

	// correct token (in terms of size)
	testData = []byte{0x7c, // token ID
		0x00, 0x01, 0x02, 0x03, // audit user ID
		0x00, 0x01, 0x02, 0x03, // effective user ID
		0x00, 0x01, 0x02, 0x03, // effective group ID
		0x00, 0x01, 0x02, 0x03, // real user ID
		0x00, 0x01, 0x02, 0x03, // real group ID
		0x00, 0x01, 0x02, 0x03, // process ID
		0x00, 0x01, 0x02, 0x03, // audit session ID
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // terminal port ID
		0x00,                   // length of address
		0x00, 0x01, 0x02, 0x03, // IPv4
	}
	size, more, err := determineTokenSize(testData)
	if err == nil {
		t.Error("expected an error on invalid address length")
	}
	testData[37] = 4 // IPv4
	size, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 42
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}

}

func Test_determineTokenSize_expanded_32bit_header_token(t *testing.T) {
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
	testData = []byte{0x15}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 14
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}

	// correct token (in terms of size)
	testData = []byte{0x15, // token ID
		0x00, 0x01, 0x02, 0x03, // number of bytes in record
		0x00, 0x01, // record version number
		0x00, 0x01, // event type
		0x00, 0x01, // event modifier / sub-type
		0x00, 0x01, 0x02, 0x03, // host address type/length
		0x00, 0x01, 0x02, 0x03, // IPv4
		0x00, 0x01, 0x02, 0x03, // seconds timestamp
		0x00, 0x01, 0x02, 0x03, // nanosecond timestamp
	}
	size, more, err := determineTokenSize(testData)
	if err == nil {
		t.Error("expected an error on invalid address type")
	}
	testData[10] = 0
	testData[11] = 0
	testData[12] = 0
	testData[13] = 4 // IPv4
	size, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 26
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}

}

func Test_determineTokenSize_expanded_64bit_header_token(t *testing.T) {
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
	testData = []byte{0x15}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 14
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}

	// correct token (in terms of size)
	testData = []byte{0x79, // token ID
		0x00, 0x01, 0x02, 0x03, // number of bytes in record
		0x00, 0x01, // record version number
		0x00, 0x01, // event type
		0x00, 0x01, // event modifier / sub-type
		0x00, 0x01, 0x02, 0x03, // host address type/length
		0x00, 0x01, 0x02, 0x03, // IPv4
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // seconds timestamp
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // nanosecond timestamp
	}
	size, more, err := determineTokenSize(testData)
	if err == nil {
		t.Error("expected an error on invalid address type")
	}
	testData[10] = 0
	testData[11] = 0
	testData[12] = 0
	testData[13] = 4 // IPv4
	size, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 35
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}

}

func Test_determineTokenSize_32bit_arg_token(t *testing.T) {
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
	testData = []byte{0x2d}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 7
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	// correct token (in terms of size)
	testData = []byte{0x2d, // token ID
		0x00,                   // argument ID
		0x00, 0x01, 0x02, 0x03, // argument value
		0x00, 0x04, // length
		0x41, 0x41, 0x41, 0x00, // actual string
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 12
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}

}

func Test_determineTokenSize_arbitrary_data_token(t *testing.T) {
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
	testData = []byte{0x21}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 3
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	// correct token (in terms of size)
	testData = []byte{0x21, // token ID
		0x00,                                           // how to print
		0x02,                                           // basic unit
		0x04,                                           // unit count
		0x01, 0x01, 0x02, 0x02, 0x03, 0x03, 0x04, 0x04, // data
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 12
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}

}

func Test_determineTokenSize_exec_args_token(t *testing.T) {
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
	testData = []byte{0x3c}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 4
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	// correct token (in terms of size)
	testData = []byte{0x3c, // token ID
		0x00, 0x00, 0x00, 0x02, // count
		0x41, 0x41, 0x41, 0x41, 0x00, // text
		0x42, 0x42, 0x42, 0x42, 0x00, // text
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 15
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}
}

func Test_determineTokenSize_exec_argv_token(t *testing.T) {
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
	testData = []byte{0x3d}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 4
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	// correct token (in terms of size)
	testData = []byte{0x3d, // token ID
		0x00, 0x00, 0x00, 0x02, // count
		0x41, 0x41, 0x41, 0x41, 0x00, // text
		0x42, 0x42, 0x42, 0x42, 0x00, // text
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 15
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}
}

func Test_determineTokenSize_group_token(t *testing.T) {
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
	testData = []byte{0x34}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 2
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	// correct token (in terms of size)
	testData = []byte{0x34, // token ID
		0x00, 0x01, // count
		0x41, 0x41, 0x41, 0x41, 0x41, // ID 1
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 7
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}
}

func Test_determineTokenSize_path_token(t *testing.T) {
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
	testData = []byte{0x23}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 2
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	// correct token (in terms of size)
	testData = []byte{0x23, // token ID
		0x00, 0x03, // path length
		0x41, 0x2f, 0x42, 0x00, // "A/B"
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 6
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}
}

func Test_determineTokenSize_path_attr_token(t *testing.T) {
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
	testData = []byte{0x25}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 2
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	// correct token (in terms of size)
	testData = []byte{0x25, // token ID
		0x00, 0x02, // count
		0x41, 0x41, 0x41, 0x00, // path 1
		0x42, 0x42, 0x42, 0x00, // path 2
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 11
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}
}

func Test_determineTokenSize_text_token(t *testing.T) {
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
	testData = []byte{0x28}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 2
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	// correct token (in terms of size)
	testData = []byte{0x28, // token ID
		0x00, 0x03, // count
		0x41, 0x41, 0x41, 0x00, // path 1
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 6
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}
}

func Test_determineTokenSize_expanded_socket_token(t *testing.T) {
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
	testData = []byte{0x7f}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 6
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	// correct token (in terms of size)
	testData = []byte{0x7f, // token ID
		0x01, 0x02, // socket domain
		0x01, 0x02, // socket type
		0x00, 0x04, // address type
		0x01, 0x02, // local port
		0x00, 0x01, 0x02, 0x03, // local address (IPv4)
		0x01, 0x02, // remote port
		0x00, 0x01, 0x02, 0x03, // remote address (IPv4)
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 19
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}
}

func Test_determineTokenSize_zonename_token(t *testing.T) {
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
	testData = []byte{0x60}
	_, more, err = determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	moreBytes := 2
	if more != moreBytes {
		t.Error("expected " + strconv.Itoa(moreBytes) + " bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	// correct token (in terms of size)
	testData = []byte{0x60, // token ID
		0x00, 0x02, // zone name length
		0x01, 0x02, 0x00, // zone name
	}
	size, more, err := determineTokenSize(testData)
	if err != nil {
		t.Error(err)
	}
	if more != 0 {
		t.Error("expected 0 bytes more to read, but only " + strconv.Itoa(more) + " were requested")
	}
	expSize := 5
	if size != expSize {
		t.Error("wrong size: expected " + strconv.Itoa(expSize) + ", got " + strconv.Itoa(size))
	}
}

func TestParseHeaderToken32bit(t *testing.T) {
	data := []byte{0x14, // token ID \
		0x00, 0x00, 0x00, 0x38, // record byte number \
		0x0b,       // version number
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
	if token.VersionNumber != 11 {
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

func Test_parsing_ExpandedProcessToken32bit(t *testing.T) {
	data := []byte{
		0x7b,                   // token ID
		0x00, 0x01, 0x02, 0x03, // audit ID
		0x00, 0x01, 0x02, 0x03, // effective user ID
		0x00, 0x01, 0x02, 0x03, // effective group ID
		0x00, 0x01, 0x02, 0x03, // real user ID
		0x00, 0x01, 0x02, 0x03, // real group ID
		0x00, 0x01, 0x02, 0x03, // process ID
		0x00, 0x01, 0x02, 0x03, // session ID
		0x00, 0x01, 0x02, 0x03, // terminal port ID
		0x00, 0x00, 0x00, 0x04, // address length -> IPv4
		0x00, 0x01, 0x02, 0x03, // actual IP
	}

	token, err := TokenFromByteInput(bytes.NewBuffer(data))
	if err != nil {
		t.Error(err.Error())
	}
	switch v := token.(type) {
	case ExpandedProcessToken32bit:
		if v.TerminalAddressLength != 0x04 {
			t.Error("invalid address length on 32 bit expanded process token")
		}
	default:
		t.Error("unexpected token found")
	}

	data = []byte{
		0x7b,                   // token ID
		0x00, 0x01, 0x02, 0x03, // audit ID
		0x00, 0x01, 0x02, 0x03, // effective user ID
		0x00, 0x01, 0x02, 0x03, // effective group ID
		0x00, 0x01, 0x02, 0x03, // real user ID
		0x00, 0x01, 0x02, 0x03, // real group ID
		0x00, 0x01, 0x02, 0x03, // process ID
		0x00, 0x01, 0x02, 0x03, // session ID
		0x00, 0x01, 0x02, 0x03, // terminal port ID
		0x00, 0x00, 0x00, 0x10, // address length -> IPv6
		0x00, 0x01, 0x02, 0x03, // actual IP
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	}
	token, err = TokenFromByteInput(bytes.NewBuffer(data))
	if err != nil {
		t.Error(err.Error())
	}
	switch token.(type) {
	case ExpandedProcessToken32bit:
	default:
		t.Error("unexpected token found")
	}

	data = []byte{
		0x7b,                   // token ID
		0x00, 0x01, 0x02, 0x03, // audit ID
		0x00, 0x01, 0x02, 0x03, // effective user ID
		0x00, 0x01, 0x02, 0x03, // effective group ID
		0x00, 0x01, 0x02, 0x03, // real user ID
		0x00, 0x01, 0x02, 0x03, // real group ID
		0x00, 0x01, 0x02, 0x03, // process ID
		0x00, 0x01, 0x02, 0x03, // session ID
		0x00, 0x01, 0x02, 0x03, // terminal port ID
		0x00, 0x00, 0x00, 0x11, // invalid address length
		0x00, 0x01, 0x02, 0x03, // actual IP
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x41,
	}
	_, err = TokenFromByteInput(bytes.NewBuffer(data))
	if err == nil {
		t.Error("expected an error on invalid length")
	}

}

func Test_small_example_token(t *testing.T) {
	data := []byte{
		0x14,                   // --- 32bit header token ID
		0x00, 0x00, 0x00, 0x38, // 56 bytes in record
		0x0b,       // version number (2991)
		0xaf, 0xc8, // event type
		0x00, 0x00, // event modifier / sub-type
		0x5a, 0x9a, 0xc2, 0xe6, // timestamp seconds
		0x00, 0x00, 0x03, 0x01, // timestamp nanoseconds
		0x28,       // --- text token ID
		0x00, 0x16, // string length (22 bytes)
		0x61, 0x75, 0x64, 0x69, // actual string
		0x74, 0x64, 0x3a, 0x3a,
		0x41, 0x75, 0x64, 0x69,
		0x74, 0x20, 0x73, 0x74,
		0x61, 0x72, 0x74, 0x75,
		0x70, 0x00,
		0x27,                   // --- return token ID
		0x00,                   // error number
		0x00, 0x00, 0x00, 0x00, // return value
		0x13,       // --- trailer token ID
		0xb1, 0x05, // trailer magic
		0x00, 0x00, 0x00, 0x38, // record byte count (56 bytes)
	}
	input := bytes.NewBuffer(data)

	// --- parse tokens single handed ---
	// parse first token
	token, err := TokenFromByteInput(input)
	if err != nil {
		t.Error(err.Error())
	}
	switch token.(type) {
	case HeaderToken32bit:
	default:
		t.Error("unexpected token found")
	}

	// parse second token
	token, err = TokenFromByteInput(input)
	if err != nil {
		t.Error(err.Error())
	}
	switch v := token.(type) {
	case TextToken:
		if v.TextLength != 22 {
			t.Error("wrong text length")
		}
		if v.Text != "auditd::Audit startup" {
			t.Error("unexpected text")
		}
	default:
		t.Error("unexpected token found")
	}

	// parse third token
	token, err = TokenFromByteInput(input)
	if err != nil {
		t.Error(err.Error())
	}
	switch v := token.(type) {
	case ReturnToken32bit:
		if v.ErrorNumber != 0 {
			t.Error("unexpected error number")
		}
		if v.ReturnValue != 0 {
			t.Error("unexpected return value")
		}
	default:
		t.Error("unexpected token found")
	}

	// parse fourth (last) token
	token, err = TokenFromByteInput(input)
	if err != nil {
		t.Error(err.Error())
	}
	switch v := token.(type) {
	case TrailerToken:
		if v.RecordByteCount != 0 {
			t.Error("unexpected record byte count")
		}
	default:
		t.Error("unexpected token found")
	}

	// --- try to parse complete record ---
	input = bytes.NewBuffer(data)
	rec, err := ReadBsmRecord(input)
	if err != nil {
		t.Error(err.Error())
	}
	if 2 != len(rec.Tokens) {
		t.Error("unexpected number od tokens in BSM record")
	}

	// --- try the generator ---
	input = bytes.NewBuffer(data)
	rcount := 0
	for _ = range RecordGenerator(input) {
		rcount += 1
		if rcount > 2 { // original + EOF
			t.Error("more records than expected")
		}
	}
}

func Test_parsing_root_login(t *testing.T) {
	data := []byte{
		0x14, // --- 32bit header token
		0x00, 0x00, 0x00, 0x61,
		0x0b,
		0x18, 0x0f,
		0x00, 0x00,
		0x5a, 0x9a, 0xc2, 0x1f,
		0x00, 0x00, 0x03, 0x63,
		0x24,                   // --- 32bit subject token
		0xff, 0xff, 0xff, 0xff, // audit ID
		0x00, 0x00, 0x00, 0x00, // effective user ID
		0x00, 0x00, 0x00, 0x00, // effective group ID
		0x00, 0x00, 0x00, 0x00, // real user ID
		0x00, 0x00, 0x00, 0x00, // real group ID
		0x00, 0x00, 0x02, 0xf2, // process ID
		0x00, 0x00, 0x02, 0xf2, // audit session ID
		0x00, 0x00, 0x00, 0x00, // terminal port ID
		0x00, 0x00, 0x00, 0x00, // machine IP address
		0x28,       // --- text token
		0x00, 0x1a, // test length (26)
		0x73, 0x75, 0x63, 0x63, // text
		0x65, 0x73, 0x73, 0x66,
		0x75, 0x6c, 0x20, 0x61,
		0x75, 0x74, 0x68, 0x65,
		0x6e, 0x74, 0x69, 0x63,
		0x61, 0x74, 0x69, 0x6f,
		0x6e, 0x00,
		0x27, // --- return token
		0x00,
		0x00, 0x00, 0x00, 0x00,
		0x13, // --- trailer token
		0xb1, 0x05,
		0x00, 0x00, 0x00, 0x61,
		0x14, // --- 32bit subject token
		0x00, 0x00, 0x00, 0x61,
		0x0b,
		0x80, 0x20,
		0x00, 0x00,
		0x5a, 0x9a, 0xc2, 0x27,
		0x00, 0x00, 0x01, 0xf9,
		0x7a, // expanded 32bit subject token
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x03, 0x35,
		0x00, 0x00, 0x03, 0x35,
		0x00, 0x00, 0x1c, 0x65,
		0x00, 0x00, 0x00, 0x04,
		0x5d, 0xb8, 0xd8, 0x26,
		0x28, // --- text token
		0x00, 0x16,
		0x73, 0x75, 0x63, 0x63,
		0x65, 0x73, 0x73, 0x66,
		0x75, 0x6c, 0x20, 0x6c,
		0x6f, 0x67, 0x69, 0x6e,
		0x20, 0x72, 0x6f, 0x6f,
		0x74, 0x00,
		0x27, // --- return token
		0x00,
		0x00, 0x00, 0x00, 0x00,
		0x13, // --- trailer token
		0xb1, 0x05,
		0x00, 0x00, 0x00, 0x61,
		0x14, // 32 bit header
		0x00, 0x00, 0x00, 0x39,
		0x0b,
		0xaf, 0xc9,
		0x00, 0x00,
		0x5a, 0x9a, 0xc2, 0x43,
		0x00, 0x00, 0x03, 0xa1,
		0x28, // --- text token
		0x00, 0x17,
		0x61, 0x75, 0x64, 0x69,
		0x74, 0x64, 0x3a, 0x3a,
		0x41, 0x75, 0x64, 0x69,
		0x74, 0x20, 0x73, 0x68,
		0x75, 0x74, 0x64, 0x6f,
		0x77, 0x6e, 0x00,
		0x27, // --- return token
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x13, // --- trailer token
		0xb1, 0x05, 0x00, 0x00, 0x00, 0x39,
	}
	input := bytes.NewBuffer(data)
	rec, err := ReadBsmRecord(input)
	if err != nil {
		t.Error(err.Error())
	}
	if 3 != len(rec.Tokens) { // subject + text + return
		t.Error("unexpected number of tokens in BSM record")
	}

	// record with expanded 32 bit subject token
	rec, err = ReadBsmRecord(input)
	if err != nil {
		t.Error(err.Error())
	}
	if 3 != len(rec.Tokens) { // subject + text + return
		t.Error("unexpected number of tokens in BSM record")
	}

	subjectToken, ok := rec.Tokens[0].(ExpandedSubjectToken32bit)
	if !ok {
		t.Error("asserting ExpandedSubjectToken32bit type failed")
	}
	if subjectToken.EffectiveUserID != 0 {
		t.Error("wrong effective user ID")
	}

	textToken, ok := rec.Tokens[1].(TextToken)
	if !ok {
		t.Error("asserting TextToken type failed")
	}
	if textToken.Text != "successful login root" {
		t.Error("unexpected string in text token")
	}

	// record with plain text token
	rec, err = ReadBsmRecord(input)
	if err != nil {
		t.Error(err.Error())
	}
	if 2 != len(rec.Tokens) { // text + return
		t.Error("unexpected number of tokens in BSM record")
	}

}

func Test_reading_from_file(t *testing.T) {
	file, err := os.Open("start_stop.bsm")
	if err != nil {
		t.Error(err)
	}
	defer file.Close()

	rcount := 0
	for _ = range RecordGenerator(file) {
		rcount += 1
		if rcount > 3 { // start + stop + EOF
			t.Error("more records than expected")
		}
	}
}
