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
	"net"
	"os"
	"strconv"
)

// ArbitraryDataToken (or 'arbitrary data' token) contains a byte stream
// of opaque (untyped) data. The size of the data is calculated as the size
// of each unit of data multiplied by the number of units of data.  A
// 'How to print' field is present to specify how to print the data, but
// interpretation of that field is not currently defined.
type ArbitraryDataToken struct {
	TokenID    byte     // token ID (1 byte): 0x21
	HowToPrint byte     // user-defined printing information (1 byte)
	BasicUnit  uint8    // size of a unit in bytes (1 byte)
	UnitCount  uint8    // number if units of data present (1 byte)
	DataItems  [][]byte // user data
}

// FileToken (or 'file' token) is used at the beginning and end of an audit
// log file to indicate when the audit log begins and ends. It includes a
// pathname so that, if concatenated together, original file boundaries are
// still observable, and gaps in the audit log can be identified.
type FileToken struct {
	TokenID        byte   // Token ID (1 byte):
	Seconds        uint32 // file timestamp (4 bytes)
	Microseconds   uint32 // file timestamp (4 bytes)
	FileNameLength uint16 // file name of audit trail (2 bytes)
	PathName       string // file name of audit trail (FileNameLength + 1 (NULL))
}

// HeaderToken32bit (or 'header' token is used to mark the beginning of a
// complete audit record, and includes the length of the total record in bytes,
// a version number for the record layout, the event type and subtype, and the
// time at which the event occurred. This type uses 32 bits to encode time
// information.
type HeaderToken32bit struct {
	TokenID         byte   // Token ID (1 byte): 0x14
	RecordByteCount uint32 // number of bytes in record (4 bytes)
	VersionNumber   uint16 // record version number (2 bytes)
	EventType       uint16 // event type (2 bytes)
	EventModifier   uint16 // event sub-type (2 bytes)
	Seconds         uint32 // record time stamp (4 bytes)
	NanoSeconds     uint32 // record time stamp (4 bytes)
}

// HeaderToken64bit (or 'header' token) is used to mark the beginning of a
// complete audit record, and includes the length of the total record in
// bytes, a version number for the record layout, the event type and subtype,
// and the time at which the event occurred. This type uses 64 bits to
// encode time information.
type HeaderToken64bit struct {
	TokenID         byte   // Token ID (1 byte): 0x74
	RecordByteCount uint32 // number of bytes in record (4 bytes)
	VersionNumber   uint16 // record version number (2 bytes)
	EventType       uint16 // event type (2 bytes)
	EventModifier   uint16 // event sub-type (2 bytes)
	Seconds         uint64 // record time stamp (8 bytes)
	NanoSeconds     uint64 // record time stamp (8 bytes)
}

// ExpandedHeaderToken32bit (or 'expanded header' token) is an expanded
// version of the 'header' token, with the addition of a machine IPv4 or
// IPv6 address. This type uses 32 bits to encode time information.
type ExpandedHeaderToken32bit struct {
	TokenID         byte   // Token ID (1 byte): 0x15
	RecordByteCount uint32 // number of bytes in record (4 bytes)
	VersionNumber   uint16 // record version number (2 bytes)
	EventType       uint16 // event type (2 bytes)
	EventModifier   uint16 // event sub-type (2 bytes)
	AddressType     uint8  // host address type and length (1 byte)
	MachineAddress  net.IP // IPv4/6 address (4/16 bytes)
	Seconds         uint32 // record time stamp (4 bytes)
	NanoSeconds     uint32 // record time stamp (4 bytes)
}

// ExpandedHeaderToken64bit (or 'expanded header' token) is an expanded
// version of the 'header' token, with the addition of a machine IPv4 or
// IPv6 address. This type uses 64 bits to encode time information.
type ExpandedHeaderToken64bit struct {
	TokenID         byte   // Token ID (1 byte): 0x79
	RecordByteCount uint32 // number of bytes in record (4 bytes)
	VersionNumber   uint16 // record version number (2 bytes)
	EventType       uint16 // event type (2 bytes)
	EventModifier   uint16 // event sub-type (2 bytes)
	AddressType     uint8  // host address type and length (1 byte)
	MachineAddress  net.IP // IPv4/6 address (4/16 bytes)
	Seconds         uint64 // record time stamp (8 bytes)
	NanoSeconds     uint64 // record time stamp (8 bytes)
}

// InAddrToken (or 'in_addr' token) holds a (network byte order) IPv4 address.
// BUGS: token layout documented in audit.log(5) appears to be in conflict with the libbsm(3) implementation of au_to_in_addr_ex(3).
type InAddrToken struct {
	TokenID   byte   // Token ID (1 byte): 0x2a
	IpAddress net.IP // IPv4 address (4 bytes)
}

// ExpandedInAddrToken (or 'expanded in_addr' token) holds a
// (network byte order) IPv4 or IPv6 address.
// TODO: determine value indicating address type
// BUGS: token layout documented in audit.log(5) appears to be in conflict with the libbsm(3) implementation of au_to_in_addr_ex(3).
type ExpandedInAddrToken struct {
	TokenID       byte   // Token ID (1 byte): 0x7e
	IpAddressType byte   // type of IP address
	IpAddress     net.IP // IP address (4/16 bytes)
}

// IpToken (or 'ip' token) contains an IP(v4) packet header in network
// byte order.
type IpToken struct {
	TokenID            byte   // Token ID (1 byte): 0x2b
	VersionAndIHL      uint8  // Version and IP header length (1 byte)
	TypeOfService      byte   // IP TOS field (1 byte)
	Length             uint16 // IP packet length in network byte order (2 bytes)
	ID                 uint16 // IP header ID for reassembly (2 bytes)
	Offset             uint16 // IP fragment offset and flags, network byte order (2 bytes)
	TTL                uint8  // IP Time-to-Live (1 byte)
	Protocol           uint8  // IP protocol number (1 byte)
	Checksum           uint16 // IP header checksum, network byte order (2 bytes)
	SourceAddress      net.IP // IPv4 source address (4 bytes)
	DestinationAddress net.IP // IPv4 destination addess (4 bytes)
}

// IPortToken (or 'iport' token) stores an IP port number in network byte order.
type IPortToken struct {
	TokenID    byte   // Token ID (1 byte): 0x2c
	PortNumber uint16 // Port number in network byte order (2 bytes)
}

// PathToken (or 'path' token) contains a pathname.
type PathToken struct {
	TokenID    byte   // Token ID (1 byte): 0x23
	PathLength uint16 // Length of path in bytes (2 bytes)
	Path       string // Path name (PathLength bytes + 1 NUL)
}

// PathAttrToken (or 'path_attr' token) contains a set of NUL-terminated path names.
// TODO: verify Token ID
type PathAttrToken struct {
	TokenID byte     // Token ID (1 byte): 0x25 ?
	Count   uint16   // Number of NUL-terminated string(s) in token (2 bytes)
	Path    []string // count NUL-terminated string(s)
}

// ProcessToken32bit (or 'process' token) contains a description of the security
// properties of a process involved as the target of an auditable event, such
// as the destination for signal delivery. It should not be confused with the
// 'subject' token, which describes the subject performing an auditable
// event. This includes both the traditional UNIX security properties, such
// as user IDs and group IDs, but also audit information such as the audit
// user ID and session. The terminal port ID is encoded using 32 bit.
type ProcessToken32bit struct {
	TokenID                byte   // Token ID (1 byte): 0x26
	AuditID                uint32 // audit user ID (4 bytes)
	EffectiveUserID        uint32 // effective user ID (4 bytes)
	EffectiveGroupID       uint32 // effective group ID (4 bytes)
	RealUserID             uint32 // real user ID (4 bytes)
	RealGroupID            uint32 // real group ID (4 bytes)
	ProcessID              uint32 // process ID (4 bytes)
	SessionID              uint32 // session ID (4 bytes)
	TerminalPortID         uint32 // terminal port ID (4 byte)
	TerminalMachineAddress net.IP // IP(v4) address of machine (4 bytes)
}

// ProcessToken64bit (or 'process' token) contains a description of the security
// properties of a process involved as the target of an auditable event, such
// as the destination for signal delivery. It should not be confused with the
// 'subject' token, which describes the subject performing an auditable
// event. This includes both the traditional UNIX security properties, such
// as user IDs and group IDs, but also audit information such as the audit
// user ID and session. The terminal port ID is encoded using 64 bit.
type ProcessToken64bit struct {
	TokenID                byte   // Token ID (1 byte): 0x77
	AuditID                uint32 // audit user ID (4 bytes)
	EffectiveUserID        uint32 // effective user ID (4 bytes)
	EffectiveGroupID       uint32 // effective group ID (4 bytes)
	RealUserID             uint32 // real user ID (4 bytes)
	RealGroupID            uint32 // real group ID (4 bytes)
	ProcessID              uint32 // process ID (4 bytes)
	SessionID              uint32 // session ID (4 bytes)
	TerminalPortID         uint64 // terminal port ID (8 byte)
	TerminalMachineAddress net.IP // IP(v4) address of machine (4 bytes)
}

// ExpandedProcessToken32bit (or 'expanded process' token contains the contents
// of the 'process' token, with the addition of a machine address type and
// variable length address storage capable of containing IPv6 addresses.
// The terminal port ID is encoded using 32 bit.
// TODO: check length of IP records (4 bytes for IPv6?)
type ExpandedProcessToken32bit struct {
	TokenID                byte   // Token ID (1 byte): 0x7b
	AuditID                uint32 // audit user ID (4 bytes)
	EffectiveUserID        uint32 // effective user ID (4 bytes)
	EffectiveGroupID       uint32 // effective group ID (4 bytes)
	RealUserID             uint32 // real user ID (4 bytes)
	RealGroupID            uint32 // real group ID (4 bytes)
	ProcessID              uint32 // process ID (4 bytes)
	SessionID              uint32 // session ID (4 bytes)
	TerminalPortID         uint32 // terminal port ID (4 byte)
	TerminalAddressLength  uint8  // length of machine address (1 byte)
	TerminalMachineAddress net.IP // IP address of machine (4 bytes)
}

// ExpandedProcessToken64bit (or 'expanded process' token contains the contents
// of the 'process' token, with the addition of a machine address type and
// variable length address storage capable of containing IPv6 addresses.
// The terminal port ID is encoded using 64 bit.
// TODO: check length of IP records (4 bytes for IPv6?)
type ExpandedProcessToken64bit struct {
	TokenID                byte   // Token ID (1 byte): 0x7d
	AuditID                uint32 // audit user ID (4 bytes)
	EffectiveUserID        uint32 // effective user ID (4 bytes)
	EffectiveGroupID       uint32 // effective group ID (4 bytes)
	RealUserID             uint32 // real user ID (4 bytes)
	RealGroupID            uint32 // real group ID (4 bytes)
	ProcessID              uint32 // process ID (4 bytes)
	SessionID              uint32 // session ID (4 bytes)
	TerminalPortID         uint64 // terminal port ID (8 byte)
	TerminalAddressLength  uint8  // length of machine address (1 byte)
	TerminalMachineAddress net.IP // IP address of machine (4 bytes)
}

// ReturnToken32bit (or 'return' token) contains a system call or library
// function return condition, including return value and error number
// associated with the global (C) variable errno. This type uses 32 bit
// to encode the return value.
type ReturnToken32bit struct {
	TokenID     byte   // Token ID (1 byte): 0x27
	ErrorNumber uint8  // errno number, or 0 if undefined (1 byte)
	ReturnValue uint32 // return value (4 bytes)
}

// ReturnToken64bit (or 'return' token) contains a system call or library
// function return condition, including return value and error number
// associated with the global (C) variable errno. This type uses 64 bit
// to encode the return value.
type ReturnToken64bit struct {
	TokenID     byte   // Token ID (1 byte): 0x72
	ErrorNumber uint8  // errno number, or 0 if undefined (1 byte)
	ReturnValue uint64 // return value (8 bytes)
}

// SubjectToken32bit (or 'subject' token) contains information on the
// subject performing the operation described by an audit record, and
// includes similar information to that found in the 'process' and
// 'expanded process' tokens.  However, those tokens are used where
// the process being described is the target of the operation, not the
// authorizing party. This type uses 32 bit to encode the terminal port ID.
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
	TerminalMachineAddress net.IP // IP address of machine (4 bytes)
}

// SubjectToken64bit (or 'subject' token) contains information on the
// subject performing the operation described by an audit record, and
// includes similar information to that found in the 'process' and
// 'expanded process' tokens.  However, those tokens are used where the
// process being described is the target of the operation, not the
// authorizing party. This type uses 64 bit to encode the terminal port ID.
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
	TerminalMachineAddress net.IP // IP address of machine (4 bytes)
}

// ExpandedSubjectToken32bit (or 'expanded subject' token)
// token consists of the same elements as the 'subject' token,
// with the addition of type/length and variable size machine
// address information in the terminal ID.
// This type uses 32 bit to encode the terminal port ID.
// TODO: check length of machine address field (4 bytes for IPv6?)
type ExpandedSubjectToken32bit struct {
	TokenID                byte   // Token ID (1 byte): 0x7a
	AuditID                uint32 // audit user ID (4 bytes)
	EffectiveUserID        uint32 // effective user ID (4 bytes)
	EffectiveGroupID       uint32 // effective group ID (4 bytes)
	RealUserID             uint32 // real user ID (4 bytes)
	RealGroupID            uint32 // real group ID (4 bytes)
	ProcessID              uint32 // process ID (4 bytes)
	SessionID              uint32 // audit session ID (4 bytes)
	TerminalPortID         uint32 // terminal port ID (4 bytes)
	TerminalAddressLength  uint8  // length of machine address
	TerminalMachineAddress net.IP // IP address of machine (4 bytes)
}

// ExpandedSubjectToken64bit (or 'expanded subject' token)
// token consists of the same elements as the 'subject' token,
// with the addition of type/length and variable size machine
// address information in the terminal ID.
// This type uses 64 bit to encode the terminal port ID.
// TODO: check length of machine address field (4 bytes for IPv6?)
type ExpandedSubjectToken64bit struct {
	TokenID                byte   // Token ID (1 byte): 0x7c
	AuditID                uint32 // audit user ID (4 bytes)
	EffectiveUserID        uint32 // effective user ID (4 bytes)
	EffectiveGroupID       uint32 // effective group ID (4 bytes)
	RealUserID             uint32 // real user ID (4 bytes)
	RealGroupID            uint32 // real group ID (4 bytes)
	ProcessID              uint32 // process ID (4 bytes)
	SessionID              uint32 // audit session ID (4 bytes)
	TerminalPortID         uint64 // terminal port ID (8 bytes)
	TerminalAddressLength  uint8  // length of machine address
	TerminalMachineAddress net.IP // IP address of machine (4 bytes)
}

// TrailerToken (or 'trailer' terminates) a BSM audit record. This token
// contains a magic number, and length that can be used to validate that
// the record was read properly.
type TrailerToken struct {
	TokenID          byte   // Token ID (1 byte): 0x13
	TrailerMagic     uint16 // trailer magic number (2 bytes): 0xb105
	RecordByteCoount uint32 // number of bytes in record (4 bytes)
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

// Determine the size (in bytes) of the current token. This is a
// utility function to determine the number of bytes (yet) to read
// from the input buffer. The return values are:
// * size - size of token in bytes
// * moreBytes - number of more bytes to read to make determination
// * err - any error that ocurred
func determineTokenSize(input []byte) (size, moreBytes int, err error) {
	size = 0
	moreBytes = 0
	err = nil

	// simple case and making sure we get a token ID
	if 0 == len(input) {
		moreBytes = 1
		return
	}

	// do magic based on token ID
	switch input[0] {
	case 0x11: // file token -> variable length
		// make sure we have enough bytes of token to
		// determine its length
		if len(input) < (1 + 4 + 4 + 2) {
			// request bytes up & incl. "File name length" field
			moreBytes = (1 + 4 + 4 + 2) - len(input)
			return
		}
		fileNameLength, local_err := bytesToUint16(input[9:11]) // read 2 bytes indicating file name length
		if local_err != nil {
			err = local_err
			return
		}
		size = 1 + 4 + 4 + 2 + int(fileNameLength) + 1 // don't forget NUL
		return
	case 0x13: // trailer token
		size = 1 + 2 + 4
	case 0x14: // 32 bit Header Token
		size = 1 + 4 + 2 + 2 + 2 + 4 + 4
	case 0x24: // 32 bit Subject Token
		size = 1 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4
	case 0x27: // 32 bit Return Token
		size = 1 + 1 + 4
	case 0x72: // 64 bit Return Token
		size = 1 + 1 + 8
	case 0x74: // 64 bit Header Token
		size = 1 + 4 + 2 + 2 + 2 + 8 + 8
	case 0x75: // 64 bit Header Token
		size = 1 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 8 + 4
	default:
		err = errors.New("can't determine the size of the given token (type)")
	}
	return
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
