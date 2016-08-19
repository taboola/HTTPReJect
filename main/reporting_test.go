package main

import (
	"testing"
	"io/ioutil"
	"strings"
	"fmt"
	"time"
	"github.com/golang/glog"
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

var base_stats_file_path = "testdata\\out\\stats"
var base_dropped_file_path = "testdata\\out\\dropped"

var stats1_file_path = base_stats_file_path + "1.txt"
var dropped1_file_path = base_dropped_file_path + "1.txt"

var stats2_file_path = base_stats_file_path + "2.txt"
var dropped2_file_path = base_dropped_file_path + "2.txt"

var stats3_file_path = base_stats_file_path + "3.txt"
var dropped3_file_path = base_dropped_file_path + "3.txt"

var stats4_file_path = base_stats_file_path + "4.txt"
var dropped4_file_path = base_dropped_file_path + "4.txt"

var stats5_file_path = base_stats_file_path + "5.txt"
var dropped5_file_path = base_dropped_file_path + "5.txt"

var stats6_file_path = base_stats_file_path + "6.txt"
var dropped6_file_path = base_dropped_file_path + "6.txt"

func TestReporter_ReportManyRequests(t *testing.T) {
	info := &reqinfo{
		URL: 		"\\test\\abc",
		TS: 		time.Now().UnixNano(),
		ReqLen: 	1024,
		TimeAccuracy: 	77,
		streamNum: 	5,
		reqNum: 	1,
	}

	stat := &stat{
		reqinfo: 	*info,
		pcapRespinfo: 	*new(pcapRespinfo),
		RTT: 		510,
		RC:		500,
		RespLen:	1024,
		respMatch: 	make([]string, 0),
	}

	repFunc := func(t *testing.T, rep *reporter) {
		for i:=0; i<100;i++ {
			rep.ReportStat(stat)
		}
	}

	rep := NewReporter(true, stats4_file_path, dropped4_file_path)

	expect := expectedFileResult{
		filePath:	stats4_file_path,
		predicate: 	func (s string) bool {
			return rep.numMismatchedRCs == 0 &&
			rep.stated == 100 &&
			rep.failed == 0 &&
			rep.dropped == 0 &&
			len(rep.rtts) == 100 &&
			rep.rtts[0] == 510 &&
			strings.Contains(s, stat.String())
		},
	}

	testReporterFile(repFunc, rep, t, expect)
}

func TestReporter_ReportRequestNoResponse(t *testing.T) {
	info := &reqinfo{
		URL: 		"\\test\\abc",
		TS: 		time.Now().UnixNano(),
		ReqLen: 	1024,
		TimeAccuracy: 	77,
		streamNum: 	5,
		reqNum: 	1,
	}

	stat := &stat{
		reqinfo: 	*info,
		pcapRespinfo: 	*new(pcapRespinfo),
		RTT: 		510,
		RC:		500,
		RespLen:	1024,
		respMatch: 	make([]string, 0),
	}

	repFunc := func(t *testing.T, rep *reporter) {
		rep.ReportStat(stat)
	}

	rep := NewReporter(true, stats5_file_path, dropped5_file_path)

	expect := expectedFileResult{
		filePath:	stats5_file_path,
		predicate: 	func (s string) bool {
			return rep.numMismatchedRCs == 0 &&
			rep.stated == 1 &&
			rep.failed == 0 &&
			rep.dropped == 0 &&
			len(rep.rtts) == 1 &&
			rep.rtts[0] == 510 &&
			strings.Contains(s, stat.String())
		},
	}

	testReporterFile(repFunc, rep, t, expect)
}

func TestReporter_ReportRequestBeforeResponse(t *testing.T) {
	info := &reqinfo{
		URL: 		"\\test\\abc",
		TS: 		time.Now().UnixNano(),
		ReqLen: 	1024,
		TimeAccuracy: 	77,
		streamNum: 	5,
		reqNum: 	1,
	}

	resp := &pcapRespinfo{
		Resptime:       info.TS + 200,
		OrigRlen:      	1024,
		OrigRC:      	500,
		OrigRTT:       	0,
		respStreamNum: 	5,
		respNum:       	1,
	}
	stat := &stat{
		reqinfo: 	*info,
		pcapRespinfo: 	*new(pcapRespinfo),
		RTT: 		510,
		RC:		500,
		RespLen:	1024,
		respMatch: 	make([]string, 0),
	}

	repFunc := func(t *testing.T, rep *reporter) {
		rep.ReportStat(stat)
		rep.ReportResponse(resp)
	}

	rep := NewReporter(true, stats6_file_path, dropped6_file_path)

	expect := expectedFileResult{
		filePath:	stats6_file_path,
		predicate: 	func (s string) bool {
			return rep.numMismatchedRCs == 0 &&
			rep.stated == 1 &&
			rep.failed == 0 &&
			rep.dropped == 0 &&
			len(rep.rtts) == 1 &&
			rep.rtts[0] == 510 &&
			strings.Contains(s, stat.String())
		},
	}

	testReporterFile(repFunc, rep, t, expect)
}


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
		predicate: func (s string) bool {
			return strings.Compare(s, info.String()) == 0
		},
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

	rep := NewReporter(true, stats2_file_path, dropped2_file_path)

	pred := func(rep *reporter) (bool, string) {
		return rep.failed == numFailed, fmt.Sprintf("Expected failed = %v got %v", numFailed, rep.failed)
	}

	testReporter(f, rep, t, pred)
}

func TestReporter_ReportUnmatchedResponse(t *testing.T) {
	respInfo := &pcapRespinfo{
		Resptime:      500,
		OrigRlen:      1024,
		OrigRC:      500,
		OrigRTT:       17,
		respStreamNum: 7,
		respNum:       7,
	}

	f := func(t *testing.T, rep *reporter) {
		rep.ReportResponse(respInfo)
	}

	rep := NewReporter(true, stats3_file_path, dropped3_file_path)

	statsRes := expectedFileResult{
		filePath: stats3_file_path,
		predicate: func (s string) bool {
			return strings.Contains(strings.ToLower(s), "unmatched resps : 1")
		},
	}

	droppedRes := newEmptyResult(dropped3_file_path)

	testReporterFile(f, rep, t, statsRes, droppedRes)
}

type reportFunc func(*testing.T, *reporter)
type expectedFileResult struct {
	filePath string
	predicate func (string) bool
}

func newEmptyResult(filePath string) expectedFileResult {
	res := expectedFileResult{
		filePath: filePath,
		predicate: func(s string) bool {return strings.Compare(s, "") == 0},
	}

	return res
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
		for _, expectedRes := range expectedResults {
			if bytes, err := ioutil.ReadFile(expectedRes.filePath); err != nil {
				return false, fmt.Sprintf("Could not open file %v due to %v", expectedRes.filePath, err)
			} else {
				got := strings.TrimSpace(string(bytes))

				if result := expectedRes.predicate(got); !result {
					return false, fmt.Sprintf("In file %v, got_str = %v",
						expectedRes.filePath, got)
				}
			}
		}
		return true, ""
	}

	testReporter(f, rep, t, pred)
}

func testReporter(f reportFunc, rep *reporter, t *testing.T, predicate func (*reporter) (bool, string)) {
	go rep.Report()
	//time.Sleep(time.Second)
	f(t, rep)

	rep.AwaitInitialization() //we need this here to prevent a race condition with the reporting functionality (see function docs)
	rep.Stop()
	rep.SyncFlush()

	//reset data
	streamReqSeqMap = make(map[streamKey]*stat)
	streamRespSeqMap = make(map[streamKey]*pcapRespinfo)

	if res, msg := predicate(rep); !res {
		t.Errorf("Failed: %v", msg)
	}

	glog.Flush()
}