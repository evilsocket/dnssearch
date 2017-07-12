// This software is a subdomain enumeration tool written by Simone Margaritelli
// (evilsocket at gmail dot com) and Copylefted under GPLv3 license.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/evilsocket/brutemachine"
	"github.com/fatih/color"
)

//Version is version
const Version = "1.0.1"

// Result to show what we've found
type Result struct {
	hostname string
	addrs    []string
	txts     []string
	cname    string // Per RFC, there should only be one CNAME
}

var (
	m *brutemachine.Machine

	g = color.New(color.FgGreen)
	y = color.New(color.FgYellow)
	r = color.New(color.FgRed)
	b = color.New(color.FgBlue)

	base        = flag.String("domain", "", "Base domain to start enumeration from.")
	wordlist    = flag.String("wordlist", "names.txt", "Wordlist file to use for enumeration.")
	consumers   = flag.Int("consumers", 8, "Number of concurrent consumers.")
	searchtxt   = flag.Bool("txt", false, "Search for TXT records")
	searchcname = flag.Bool("cname", false, "Show CNAME results")
	searcha     = flag.Bool("a", true, "Show A results")
)

// DoRequest actually handles the DNS lookups
func DoRequest(sub string) interface{} {
	hostname := fmt.Sprintf("%s.%s", sub, *base)
	thisresult := Result{}
	if *searcha {
		if addrs, err := net.LookupHost(hostname); err == nil {
			thisresult.hostname = hostname
			thisresult.addrs = addrs
		}
	}
	if *searchtxt {
		if txts, err := net.LookupTXT(hostname); err == nil {
			thisresult.hostname = hostname
			thisresult.txts = txts
		}
	}
	if *searchcname {
		if cname, err := net.LookupCNAME(hostname); err == nil {
			thisresult.hostname = hostname
			thisresult.cname = cname
		}
	}

	if thisresult.hostname == "" {
		return nil
	}
	return thisresult
}

// OnResult prints out the results of a lookup
func OnResult(res interface{}) {
	result, ok := res.(Result)
	if !ok {
		r.Printf("Error while converting result.\n")
		return
	}

	g.Printf("%25s", result.hostname)
	if *searcha {
		fmt.Printf(" : A %v", result.addrs)
	}
	if *searchtxt {
		fmt.Printf(" : TXT %v", result.txts)
	}
	if *searchcname {
		fmt.Printf(" : CNAME %v", result.cname)
	}
	fmt.Printf("\n")
}

func main() {
	setup()

	m = brutemachine.New(*consumers, *wordlist, DoRequest, OnResult)
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
	fmt.Printf(" v%s\n\n", Version)

	flag.Parse()

	if *base == "" {
		fmt.Println("Invalid or empty domain specified.")
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
