package main

import (
	"testing"
	"io/ioutil"
	"strings"
	"fmt"
	//"time"
)

func TestJoin(t *testing.T) {
	strs := []string {"a", "b", "c"}
	var del byte = 't'
	want := "atbtc"
	if got := join(strs, del); got != want{
		t.Errorf("Expected %s but got %s", want, got)
	}

	var del2 byte = ','
	want2 := "a,b,c"
	if got2 := join(strs, del2); want2 != got2 {
		t.Errorf("Wanted %s but got %s", want2, got2)
	}
}

func TestJoinEmptyArray(t *testing.T) {
	strs := []string {}
	var del byte = ','
	want := ""
	if got := join(strs, del); want != got {
		t.Errorf("Wanted %s got %s", want, got)
	}
}

func TestJoinNilArray(t *testing.T) {
	var strs []string = nil
	var del byte = ','
	want := ""
	if got := join(strs, del); want != got {
		t.Errorf("Wanted %s got %s", want, got)
	}
}


var stats1_file_path = "testdata\\stats1.txt"
var dropped1_file_path = "testdata\\dropped1.txt"

func TestReporter_ReportDropped(t *testing.T) {
	info := &reqinfo{
		URL: 	      "\\test\\abc",
		TS:           1000,
		ReqLen:       1024,
		TimeAccuracy: -100,
		streamNum:    4,
		reqNum:       511,
	}

	repFunc := func(t *testing.T, rep *reporter) {
		rep.ReportDropped(info)
	}

	rep := NewReporter(true, stats1_file_path, dropped1_file_path)

	expect := expectedFileResult{
		filePath: dropped1_file_path,
		expectedData: info.String(),
	}

	testReporterFile(repFunc, rep, t, expect)
}

func TestReporter_ReportFailedStat(t *testing.T) {
	numFailed := 15
	f := func(t *testing.T, rep *reporter) {
		for i := 0; i < numFailed; i++ {
			rep.ReportFailedStat()
		}
	}

	rep := NewReporter(true, stats1_file_path, dropped1_file_path)

	pred := func(rep *reporter) (bool, string) {
		return rep.failed == numFailed, fmt.Sprintf("Expected failed = %v got %v", numFailed, rep.failed)
	}

	testReporter(f, rep, t, pred)
}

type reportFunc func(*testing.T, *reporter)
type expectedFileResult struct {
	filePath string
	expectedData string
}

// A general wrapper for testing reporter functionality.
// Since there is currently quite some boilerplate around proper initialization and shutdown of the reporter,
// this should keep the boilerplate to a single place.
// The idea is that f (the reportFunc) does the actual logic that requires testing,
// rep is the reporter which we are testing,
// t is the testing context,
// expectedResults are the expected (file, data) couples - yes, we are currently comparing file-to-string. (maybe file-to-file?)
func testReporterFile(f reportFunc, rep *reporter, t *testing.T, expectedResults ...expectedFileResult) {

	pred := func(r *reporter) (bool, string) {
		for i, expectedRes := range expectedResults {
			if bytes, err := ioutil.ReadFile(expectedRes.filePath); err != nil {
				return false, fmt.Sprintf("Could not open file %v due to %v", expectedRes.filePath, err)
			} else {
				want := strings.TrimSpace(expectedRes.expectedData)
				got := strings.TrimSpace(string(bytes))

				if compareResult := strings.Compare(want, got); compareResult != 0 {
					return false, fmt.Sprintf("In file(#%v): %v\nWanted: " +
					"compare = 0, got: compare = %v, want_str = %v, got_str = %v",
						i, expectedRes.filePath, compareResult, want, got)

				}
			}
		}
		return true, ""
	}

	testReporter(f, rep, t, pred)
}

func testReporter(f reportFunc, rep *reporter, t *testing.T, predicate func (*reporter) (bool, string)) {
	go rep.Report()
	f(t, rep)

	rep.AwaitInitialization() //we need this here to prevent a race condition with the reporting functionality (see function docs)
	rep.Stop()
	rep.SyncFlush()

	if res, msg := predicate(rep); !res {
		t.Errorf("Failed: %v", msg)
	}
}