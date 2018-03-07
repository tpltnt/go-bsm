// test parsing of BSM files
package main

import (
	"bytes"
	"testing"
)

func TestRecordsFromFile(t *testing.T) {
	data := []byte{0x00}
	err := RecordsFromFile(bytes.NewBuffer(data))
	if err == nil {
		t.Error("one byte record should yield an error")
	}
}
