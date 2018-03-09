// Parse BSM files
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io"
	"log"
	"math"
	"os"
	"strconv"
)

// The 'file' token is used at the beginning and end of an audit log file
// to indicate when the audit log begins and ends. It includes a pathname
// so that, if concatenated together, original file boundaries are still
// observable, and gaps in the audit log can be identified.
type FileToken struct {
	TokenID        byte   // Token ID (1 byte):
	Seconds        uint32 // file timestamp (4 bytes)
	Microseconds   uint32 // file timestamp (4 bytes)
	FileNameLength uint16 // file name of audit trail (2 bytes)
	PathName       string // file name of audit trail (FileNameLength + 1 (NULL))
}

// The 'header' token is used to mark the beginning of a complete audit
// record, and includes the length of the total record in bytes, a version
// number for the record layout, the event type and subtype, and the time at
// which the event occurred. This type uses 32 bits to encode time information.
type HeaderToken32bit struct {
	TokenID         byte   // Token ID (1 byte): 0x14
	RecordByteCount uint32 // number of bytes in record (4 bytes)
	VersionNumber   uint16 // record version number (2 bytes)
	EventType       uint16 // event type (2 bytes)
	EventModifier   uint16 // event sub-type (2 bytes)
	Seconds         uint32 // record time stamp (4 bytes)
	NanoSeconds     uint32 // record time stamp (4 bytes)
}

// The 'header' token is used to mark the beginning of a complete audit
// record, and includes the length of the total record in bytes, a version
// number for the record layout, the event type and subtype, and the time at
// which the event occurred. This type uses 64 bits to encode time information.
type HeaderToken64bit struct {
	TokenID         byte   // Token ID (1 byte): 0x74
	RecordByteCount uint32 // number of bytes in record (4 bytes)
	VersionNumber   uint16 // record version number (2 bytes)
	EventType       uint16 // event type (2 bytes)
	EventModifier   uint16 // event sub-type (2 bytes)
	Seconds         uint64 // record time stamp (8 bytes)
	NanoSeconds     uint64 // record time stamp (8 bytes)
}

// The `trailer' terminates a BSM audit record. This token contains a magic
// number, and length that can be used to validate that the record was
// read properly.
type TrailerToken struct {
	TokenID          byte   // Token ID (1 byte): 0x13
	TrailerMagic     uint16 // trailer magic number (2 bytes): 0xb105
	RecordByteCoount uint32 // number of bytes in record (4 bytes)
}

// The 'return' token contains a system call or library function return
// condition, including return value and error number associated with the
// global (C) variable errno. This type uses 32 bit to encode the return
// value.
type ReturnToken32bit struct {
	TokenID     byte   // Token ID (1 byte): 0x27
	ErrorNumber uint8  // errno number, or 0 if undefined (1 byte)
	ReturnValue uint32 // return value (4 bytes)
}

// The 'return' token contains a system call or library function return
// condition, including return value and error number associated with the
// global (C) variable errno. This type uses 64 bit to encode the return
// value.
type ReturnToken64bit struct {
	TokenID     byte   // Token ID (1 byte): 0x72
	ErrorNumber uint8  // errno number, or 0 if undefined (1 byte)
	ReturnValue uint64 // return value (8 bytes)
}

// The 'subject' token contains information on the subject performing the
// operation described by an audit record, and includes similar information
// to that found in the 'process' and 'expanded process' tokens.  However,
// those tokens are used where the process being described is the target
// of the operation, not the authorizing party. This type uses 32 bit
// to encode the terminal port ID.
type SubjectToken32bit struct {
	TokenID                byte   // Token ID (1 byte): 0x24
	AuditID                uint32 // audit user ID (4 bytes)
	EffectiveUserID        uint32 // effective user ID (4 bytes)
	EffectiveGroupID       uint32 // effective group ID (4 bytes)
	RealUserID             uint32 // real user ID (4 bytes)
	RealGroupID            uint32 // real group ID (4 bytes)
	ProcessID              uint32 // process ID (4 bytes)
	SessionID              uint32 // audit session ID (4 bytes)
	TerminalPortID         uint32 // terminal port ID (4 bytes)
	TerminalMachineAddress uint32 // IP address of machine (4 bytes)
}

// The 'subject' token contains information on the subject performing the
// operation described by an audit record, and includes similar information
// to that found in the 'process' and 'expanded process' tokens.  However,
// those tokens are used where the process being described is the target
// of the operation, not the authorizing party. This type uses 64 bit
// to encode the terminal port ID.
type SubjectToken64bit struct {
	TokenID                byte   // Token ID (1 byte): 0x75
	AuditID                uint32 // audit user ID (4 bytes)
	EffectiveUserID        uint32 // effective user ID (4 bytes)
	EffectiveGroupID       uint32 // effective group ID (4 bytes)
	RealUserID             uint32 // real user ID (4 bytes)
	RealGroupID            uint32 // real group ID (4 bytes)
	ProcessID              uint32 // process ID (4 bytes)
	SessionID              uint32 // audit session ID (4 bytes)
	TerminalPortID         uint64 // terminal port ID (8 bytes)
	TerminalMachineAddress uint32 // IP address of machine (4 bytes)
}

// Go has this unexpected behaviour, where Uvarint() aborts
// after reading the first byte if it is 0x00 (no matter
// what comes later) and can eat max 2 bytes. I expected 8 since
// Uvarint() returns a uint64. Anyhow, I decided to roll my own.

// Convert bytes to uint32 (and abstract away some quirks).
func bytesToUint32(input []byte) (uint32, error) {
	if 4 < len(input) {
		return 0, errors.New("more than four bytes given -> risk of overflow")
	}
	result := uint32(0)
	for i := 0; i < len(input); i++ {
		coeff := uint32(input[i])
		exp := float64(len(input) - i - 1)
		powerOf256 := uint32(math.Pow(float64(256), exp))
		result += coeff * powerOf256
	}
	return result, nil
}

// Convert bytes to uint32 (and abstract away some quirks).
func bytesToUint16(input []byte) (uint16, error) {
	if 2 < len(input) {
		return 0, errors.New("more than four bytes given -> risk of overflow")
	}
	result := uint16(0)
	for i := 0; i < len(input); i++ {
		coeff := uint16(input[i])
		exp := float64(len(input) - i - 1)
		powerOf256 := uint16(math.Pow(float64(256), exp))
		result += coeff * powerOf256
	}
	return result, nil
}

// ParseHeaderToken32bit parses a HeaderToken32bit out of the given bytes.
func ParseHeaderToken32bit(input []byte) (HeaderToken32bit, error) {
	ptr := 0
	token := HeaderToken32bit{}

	// (static) length check
	if len(input) != 19 {
		return token, errors.New("invalid length of 32bit header token")
	}

	// read token ID
	tokenID := input[ptr]
	if tokenID != 0x14 {
		return token, errors.New("token ID mismatch")
	}
	token.TokenID = tokenID
	ptr += 1

	// read record byte count (4 bytes)
	data32, err := bytesToUint32(input[ptr : ptr+4])
	if err != nil {
		return token, err
	}
	token.RecordByteCount = data32
	ptr += 4

	// read version number (2 bytes)
	data16, err := bytesToUint16(input[ptr : ptr+2])
	if err != nil {
		return token, err
	}
	token.VersionNumber = data16
	ptr += 2

	// read event type (2 bytes)
	data16, err = bytesToUint16(input[ptr : ptr+2])
	if err != nil {
		return token, err
	}
	token.EventType = data16
	ptr += 2

	// read event sub-type / modifier
	data16, err = bytesToUint16(input[ptr : ptr+2])
	if err != nil {
		return token, err
	}
	token.EventModifier = data16
	ptr += 2

	// read seconds
	data32, err = bytesToUint32(input[ptr : ptr+4])
	if err != nil {
		return token, err
	}
	token.Seconds = data32
	ptr += 4

	// read nanoseconds
	data32, err = bytesToUint32(input[ptr : ptr+4])
	if err != nil {
		return token, err
	}
	token.NanoSeconds = data32

	return token, nil
}

// RecordsFromFile yields a generator for all records contained
// in the given file.
func RecordsFromFile(input io.Reader) error {
	oneByte := []byte{0x00}
	twoBytes := []byte{0x00, 0x00}
	fourBytes := []byte{0x00, 0x00, 0x00, 0x00}
	n, err := input.Read(oneByte)
	if nil != err {
		return err
	}
	if n != 1 {
		return errors.New("read " + strconv.Itoa(n) + " bytes, but wanted exactly 1")
	}
	tokenID := oneByte[0]
	switch tokenID {
	case 0x14: // HeaderToken32bit
		token := HeaderToken32bit{
			TokenID: tokenID,
		}
		// read record byte count
		n, err = input.Read(fourBytes)
		if nil != err {
			return err
		}
		if n != 1 {
			return errors.New("read " + strconv.Itoa(n) + " bytes, but wanted exactly 4")
		}
		data, n := binary.Uvarint(fourBytes)
		if n != 4 {
			return errors.New("decoded wrong number of bytes when reading record byte count")
		}
		token.RecordByteCount = uint32(data)

		// read version number
		n, err = input.Read(twoBytes)
		if nil != err {
			return err
		}
		if n != 2 {
			return errors.New("read " + strconv.Itoa(n) + " bytes, but wanted exactly 2")
		}
		data, n = binary.Uvarint(twoBytes)
		if n != 2 {
			return errors.New("decoded wrong number of bytes when reading version number")
		}
		token.VersionNumber = uint16(data)

		// read event type
		n, err = input.Read(twoBytes)
		if nil != err {
			return err
		}
		if n != 2 {
			return errors.New("read " + strconv.Itoa(n) + " bytes, but wanted exactly 2")
		}
		data, n = binary.Uvarint(twoBytes)
		if n != 2 {
			return errors.New("decoded wrong number of bytes when reading event type")
		}
		token.EventType = uint16(data)

		// read event sub-type / modifier
		n, err = input.Read(twoBytes)
		if nil != err {
			return err
		}
		if n != 2 {
			return errors.New("read " + strconv.Itoa(n) + " bytes, but wanted exactly 2")
		}
		data, n = binary.Uvarint(twoBytes)
		if n != 2 {
			return errors.New("decoded wrong number of bytes when reading event modifier")
		}
		token.EventModifier = uint16(data)

		// read seconds
		n, err = input.Read(fourBytes)
		if nil != err {
			return err
		}
		if n != 4 {
			return errors.New("read " + strconv.Itoa(n) + " bytes, but wanted exactly 4")
		}
		data, n = binary.Uvarint(twoBytes)
		if n != 4 {
			return errors.New("decoded wrong number of bytes when reading timestamp seconds")
		}
		token.Seconds = uint32(data)

		// read nanoseconds
		n, err = input.Read(fourBytes)
		if nil != err {
			return err
		}
		if n != 4 {
			return errors.New("read " + strconv.Itoa(n) + " bytes, but wanted exactly 4")
		}
		data, n = binary.Uvarint(twoBytes)
		if n != 4 {
			return errors.New("decoded wrong number of bytes when reading timestamp nanoseconds")
		}
		token.NanoSeconds = uint32(data)

		fmt.Println(spew.Sdump(token))
	default:
		return errors.New("new token ID found: " + spew.Sdump(tokenID))
	}
	return nil
}

func main() {
	// handle CLI
	flag.String("auditfile", "", "FreeBSD audit file to parse")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	// open file to process
	aFilePath := viper.GetString("auditfile")
	if 0 != len(aFilePath) {
		file, err := os.Open(aFilePath)
		if err != nil {
			log.Fatal("Could not open input file", err)
		}
		defer file.Close()
	}
}
