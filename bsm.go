// Parse BSM files
package main

import (
	"flag"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"log"
	"os"
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
