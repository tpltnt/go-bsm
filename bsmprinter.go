// A simple tool to print BSM audit records
package main

import (
	"flag"
	//"github.com/davecgh/go-spew/spew"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"log"
	"os"
)

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
