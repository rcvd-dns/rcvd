// SPDX-License-Identifier: MIT
//go:build debugpprof

// This file is compiled ONLY when built with `-tags debugpprof`. It exposes a net/http/pprof
// endpoint so we can capture live CPU + goroutine profiles from a running rcvd — used to
// root-cause the Issue 29 CPU burn (a leak that accumulates over a process's lifetime, cleared
// by restart). It is deliberately absent from every production build: no build script passes
// this tag, so net/http/pprof is never even linked into the shipped binary.
//
// Enable at runtime by setting RCVD_PPROF_ADDR (e.g. "0.0.0.0:6060"). If unset, no listener
// starts even in a debugpprof build.
package main

import (
	"log"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof/* on http.DefaultServeMux
	"os"
)

func init() {
	addr := os.Getenv("RCVD_PPROF_ADDR")
	if addr == "" {
		return
	}
	go func() {
		log.Printf("[debugpprof] pprof listener on http://%s/debug/pprof/", addr)
		// DefaultServeMux carries the pprof handlers registered by the blank import above.
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("[debugpprof] pprof listener exited: %v", err)
		}
	}()
}
