package main

import (
	"testing"
	"io/ioutil"
	"strings"
	"fmt"
	"time"
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


///////////////////////////////////////////////////////////////////////////////////////////////////


var stats1_file_path = "testdata\\stats1.txt"
var dropped1_file_path = "testdata\\dropped1.txt"

func TestRecordRefactored(t *testing.T) {
	info := &reqinfo{
		URL: 	      "\\test\\abc",
		TS:           1000,
		ReqLen:       1024,
		TimeAccuracy: -100,
		streamNum:    4,
		reqNum:       511,
	}

	repFunc := func(t *testing.T, rep *reporter) {
		fmt.Println("hello")
		rep.ReportDropped(info)
	}

	rep := NewReporter(true, stats1_file_path, dropped1_file_path)

	expect := expectedFileResult{
		filePath: dropped1_file_path,
		expectedData: info.String(),
	}

	reporterTestHelper(repFunc, rep, t, expect)
}

type reportFunc func(*testing.T, *reporter)
type expectedFileResult struct {
	filePath string
	expectedData string
}

func reporterTestHelper(f reportFunc, rep *reporter, t *testing.T, expectedResults ...expectedFileResult) {

	go rep.Report()
	time.Sleep(1 * time.Second)
	f(t, rep)
	rep.Stop()
	rep.SyncFlush()

	for i, expectedRes := range expectedResults {
		if bytes, err := ioutil.ReadFile(expectedRes.filePath); err != nil {
			t.Errorf("Could not open file %v due to %v", expectedRes.filePath, err)
		} else {
			want := strings.TrimSpace(expectedRes.expectedData)
			got := strings.TrimSpace(string(bytes))

			if compareResult := strings.Compare(want, got); compareResult != 0 {
				t.Errorf("In file(#%v): %v\nWanted: " +
				"compare = 0, got: compare = %v, want_str = %v, got_str = %v",
					i, expectedRes.filePath, compareResult, want, got)
			}
		}
	}
}