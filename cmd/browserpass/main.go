package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/browserpass/browserpass"
	"github.com/browserpass/browserpass/protector"
)

const VERSION = "3.0.0"

func main() {
	protector.Protect("stdio rpath proc exec getpw")
	log.SetPrefix("[Browserpass] ")

	showVersion := flag.Bool("v", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("Browserpass host app version:", VERSION)
		os.Exit(0)
	}

	if err := browserpass.Run(os.Stdin, os.Stdout); err != nil && err != io.EOF {
		log.Fatal(err)
	}
}
