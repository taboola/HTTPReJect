package main

import (
	"testing"
	"sync/atomic"
)

// Make sure the int64 fields of ReaderAndTime struct are 8-byte aligned.
// If they are not, this test will fail on win32, ARM (or win64/linux running with GOARCH=386),
// Perform atomic read&write of both fields to ensure both are placed correctly.
// Run this test with GOARCH=386
func TestReaderAndTimeAlignment(*testing.T) {
	rat := new(readerAndTime)
	atomic.AddInt64(&rat.unixNano, 10)
	atomic.AddInt64(&rat.lastUnixNano, 10)
}