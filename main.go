// This software is a subdomain enumeration tool written by Simone Margaritelli
// (evilsocket at gmail dot com) and Copylefted under GPLv3 license.
package main

import (
	"flag"
	"fmt"
	"github.com/evilsocket/brutemachine"
	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/fatih/color"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const Version = "1.0.0"

type Result struct {
	hostname string
	addrs []string
}

var (
	m *brutemachine.Machine

	g = color.New(color.FgGreen)
	y = color.New(color.FgYellow)
	r = color.New(color.FgRed)
	b = color.New(color.FgBlue)

	base      = flag.String("domain", "", "Base domain to start enumeration from.")
	wordlist  = flag.String("wordlist", "names.txt", "Wordlist file to use for enumeration.")
	consumers = flag.Int("consumers", 8, "Number of concurrent consumers.")
)

func DoRequest(sub string) interface{} {
	hostname := fmt.Sprintf("%s.%s", sub, *base)
	if addrs, err := net.LookupHost(hostname); err == nil {
		return Result{ hostname: hostname, addrs: addrs }
	}
	
	return nil
}

func OnResult(res interface{}) {
	result, ok := res.(Result)
	if !ok {
		r.Printf( "Error while converting result.\n" )
		return
	}

	g.Printf( "%25s", result.hostname )
	fmt.Printf( " : %v\n", result.addrs )
}

func main() {
	setup()

	m = brutemachine.New( *consumers, *wordlist, DoRequest, OnResult)
    if err := m.Start(); err != nil {
        panic(err)
    }

    m.Wait()

	g.Println("\nDONE")

	printStats()
}

// Do some initialization.
func setup() {
	r.Printf("dnssearch")
	fmt.Printf( " v%s\n\n", Version )

	flag.Parse()

	if *base = domainutil.Domain(*base); *base == "" {
		fmt.Println( "Invalid or empty domain specified." )
		flag.Usage()
		os.Exit(1)
	}

	// if interrupted, print statistics and exit
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		r.Println("\nINTERRUPTING ...")
		printStats()
		os.Exit(0)
	}()
}

// Print some stats
func printStats() {
	m.UpdateStats()

	fmt.Println("")
	fmt.Println("Requests :", m.Stats.Execs)
	fmt.Println("Results  :", m.Stats.Results)
	fmt.Println("Time     :", m.Stats.Total.Seconds(), "s")
	fmt.Println("Req/s    :", m.Stats.Eps)
}

