/*

Copyright 2016 Taboola Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Some code borrowed from https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

const timestampDiffQueryName = "pcapreplayts"

var capFilt = flag.String("f", "tcp and dst port 80", "pcap filter")
var pcapFilename = flag.String("p", "", "PCAP filename")
var clockrate = flag.Float64("r", 1.0, "Playback rate. 2.0 would play a 2 hour pcap in 1 hour")
var forceRate = flag.Float64("forceRate", 0.0, "Force playback rate to num requests/second")
var serverURL = flag.String("s", "http://localhost:80", "server URL where we send replayed http traffic to")
var overrideHost = flag.String("forceHostHeader", "", "Force the host header to this value.")
var statOutfile = flag.String("t", "", "path/filename for statistical output")
var droppedOutfile = flag.String("logDropped", "", "path/filename to log dropped request info")
var readAheadTime = flag.Float64("pcapReadAheadTime", .1, "pcap file read ahead time in seconds.")
var maxInaccuracy = flag.Float64("maxInaccuracy", 0.0, "DEBUG: if non-zero, program exits if it falls behind or ahead")
var maxInflight = flag.Uint64("maxInflight", 256, "Max inflight at any given time")
var dropLaterThan = flag.Float64("dropLaterThan", 0.0, "Drop requests later than num seconds.")
var readResponse = flag.Bool("readResponse", true, "expect response in pcap")
var inflightChan chan bool
var rateLimitWarnings = flag.String("rateLimitWarnings", "1s", "Rate Limit Warnings")
var addDTQuery = flag.Bool("addDTQuery", false, "Adds "+timestampDiffQueryName+" to queries with delta time")
var addToQuery = flag.String("addToQuery", "", "Add arbitrary string to query.  Should be in the form of parm=val")
var noSend = flag.Bool("noSend", false, "Don't actually send any queries")
var dumpPackets = flag.Bool("dumpPackets", false, "Dump all packets to stdout for debug")
var stopAfterNumReqs = flag.Uint64("stopAfterNumReqs", 0, "exit after num reqs if non zero")
var flushPeriod = flag.Float64("pcapFlushPeriod", 30.0, "Flush streams with missing packets after this amount of time (seconds)")
var filterReqURLs = flag.String("filterRequestURLs", "", "regex to send only matching requests from pcap")
var respCaptureString = flag.String("respCapture", "", "regex capture to run against response body")
var grabTheWholeURL = flag.Bool("grabEntireURL", false, "log the entire URL (rather than just the path)")
var grabTheWholeResponse = flag.Bool("grabEntireResponse", false, "log the entire replay response")
var reReqURLs *regexp.Regexp
var reRespCapture *regexp.Regexp
var rateLimitWarningsDuration time.Duration
var numConcurrentStreams uint64 = 0
var numStreams uint64 = 0
var totNumReqs uint64 = 0
var numProxySent uint64 = 0
var numProxyInFlight uint64 = 0
var numProxySleeping uint64 = 0
var numLateDropped uint64 = 0
var numPcapReqErrs uint64 = 0
var numPcapRespErrs uint64 = 0
var numBadStreams uint64 = 0

// Global to get packet info in httpStreamFactory New:
var curPacket *gopacket.Packet

var flawedReqStreams = 0
var flawedRespStreams = 0

// high water marks:
var concurrentStreamHWM uint64 = 0
var reqPerStreamHWM uint64 = 0

var proxyURL *url.URL
var replayStartTime time.Time
var firstPcapTimestamp time.Time
var firstTimestampUnixNano int64
var numFlushed = 0
var numClosed = 0

var numPackets = 0

var readWaitGroup sync.WaitGroup  // wait group for stream readers
var proxyWaitGroup sync.WaitGroup // wait group for proxys
var streamWaitingOnData uint64 = 0

// Stuff to get multiple string command line parameters out of golang flag:
var getParmsList multiParm

type multiParm []string

func (this *multiParm) String() string {
	return fmt.Sprintf("%d", *this)
}

func (this *multiParm) Set(value string) error {
	*this = append(*this, value)

	return nil
}

// Create our own client transport for use in our httpClient
// The purpose of this clientTransport is to disable keep alives - disable connection caching/reuse
// so that connections are closed as soon as the request is sent and response is received.
// TODO: eventually we should support a pool of connections that are reused
var roundTripTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	Dial: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial,
	TLSHandshakeTimeout: 10 * time.Second,
	DisableKeepAlives:   true,
}

type stat struct {
	reqinfo
	pcapRespinfo
	RTT       float64  // Round Trip Time
	RC        int      // Return Code
	RespLen   int      // Response length
	respMatch []string // matching captures from the response
}

func (this *stat) String() string {

	var extraParms string
	if this.getParms == nil || len(this.getParms) == 0 {
		extraParms = ""
	} else {
		var buffer bytes.Buffer
		for _, parm := range this.getParms {
			buffer.WriteByte(',')
			buffer.WriteString(parm)
		}

		extraParms = buffer.String()
	}

	var respMatches string
	if this.respMatch == nil || len(this.respMatch) == 0 {
		respMatches = ""
	} else {
		var buffer bytes.Buffer
		for _, match := range this.respMatch {
			buffer.WriteByte(',')
			buffer.WriteString(match)
		}

		respMatches = buffer.String()
	}

	return fmt.Sprintf("%v,%s,%03d,%f,%d,%d,%f,%d,%d,%d,%03d,%f,%f%s%s",
		time.Unix(0, this.TS), this.URL, this.RC, this.RTT, this.ReqLen, this.RespLen, this.TimeAccuracy, this.streamNum,
		this.reqNum, this.OrigRlen, this.OrigRC, this.OrigRTT, this.wallDiff, extraParms, respMatches)
}

type reqinfo struct {
	URL          string
	TS           int64    // Nanos since epoch filetime
	wallDiff     float64  // seconds since start of processing (rate adjusted)
	ReqLen       int      // Request length
	TimeAccuracy float64  // How late when ready to send
	streamNum    uint64   // Stream number starting at 1 for first stream in pcap
	reqNum       uint64   // request number (per stream)
	getParms     []string // extra get parm
}

type pcapRespinfo struct {
	Resptime      int64
	OrigRlen      int
	OrigRC        int
	OrigRTT       float64
	respStreamNum uint64
	respNum       uint64
}

func (this *reqinfo) String() string {
	return fmt.Sprintf("%v,%s,%d,%f",
		this.TS, this.URL, this.ReqLen, this.TimeAccuracy)
}

var statRepChan chan *stat
var pcapRespRepChan chan *pcapRespinfo
var droppedRepChan chan *reqinfo

// netKey is used to map bidirectional streams to each other, mapping the http reqs from the pcap to the http resp.
// taken from: https://github.com/google/gopacket/blob/master/examples/bidirectional/main.go
type netKey struct {
	net, transport gopacket.Flow
}

func (this *netKey) Reverse() *netKey {
	return &netKey{this.net.Reverse(), this.transport.Reverse()}
}

// streamKey is a higher level mapping, mapping the stream number and sub req/resp to each other.
type streamKey struct {
	streamNum, streamSeq uint64
}

var pcapNetReqRespMap = make(map[netKey]uint64)

// We will have two maps as we don't know the order that requests/responses will be processed after
// reading from the pcap as they will race:
var streamReqSeqMap = make(map[streamKey]*stat)
var streamRespSeqMap = make(map[streamKey]*pcapRespinfo)

type RunnerType int

const (
	Request  RunnerType = iota
	Response RunnerType = iota
	Error    RunnerType = iota
)

type readerAndTime struct {
	tcpreader.ReaderStream
	unixNano       int64
	lastUnixNano   int64
	pcapStreamSide chan RunnerType
	started        bool
	key            *netKey
	matched        bool
	oneSided       bool
}

// Override so that when streams die before they are even started we don't wait for them to start when they never will.
func (this *readerAndTime) ReassemblyComplete() {

	// If we are stuck waiting to be started then kick us off:
	if !this.started {
		atomic.AddUint64(&numBadStreams, 1)
		glog.V(2).Infof("ReassemblyComplete on an unstarted stream. %v:%v\n", this.key.net, this.key.transport)
		this.pcapStreamSide <- Error
	}

	// now chain to the "super" JIC:
	this.ReaderStream.ReassemblyComplete()
}

// override Reassembled so that we can stick the timestamp into our struct
func (this *readerAndTime) Reassembled(reassembly []tcpassembly.Reassembly) {
	packetUnixNano := reassembly[len(reassembly)-1].Seen.UnixNano()

	if !this.started {
		// this is our first packet:
		this.started = true

		// Each stream's first packet should be a SYN.  However we may have missing packets in our pcap.  If its not
		// a SYN, then lets assume its a request from client to server:
		if !(*curPacket).TransportLayer().(*layers.TCP).SYN {
			glog.V(1).Infof("Missing SYN on stream.  Assuming req. %v:%v", this.key.net, this.key.transport)
			this.pcapStreamSide <- Request
		} else if (*curPacket).TransportLayer().(*layers.TCP).ACK {
			// SYN-ACK is sent from the server.
			// If we're not supposed to see responses, something's gone wrong:
			if !*readResponse {
				glog.Fatalf("Unexpected server response in pcap : %v.  Perhaps alter your pcap filter?  Exiting!",
					curPacket)
			}

			glog.V(2).Infof("About to report client side response: %v\n", this)

			// Tell the runner that this is a response stream:
			this.pcapStreamSide <- Response
		} else {

			glog.V(2).Infof("About to report client side request: %v\n", this)

			// SYN from the client.  Tell the runner this is a request stream:
			this.pcapStreamSide <- Request
		}

	} else {
		// Well before the first reassembled non-start packet we should already have setup our other side stream
		// In case this packet capture is corrupted, or one sided, make sure the other side map is clean
		if !this.oneSided && !this.matched {
			if snum, stillThere := pcapNetReqRespMap[*this.key.Reverse()]; stillThere {
				glog.V(1).Infof("Reassembled: found one sided connection on stream :%d.  Filetime: %v.  Deleting key.\n", snum, reassembly[0].Seen)
				delete(pcapNetReqRespMap, *this.key.Reverse())
				this.oneSided = true
			} else {
				this.matched = true
			}
		}
	}

	// packets may have dropped and been retransmitted.  The result is reassembled packets with
	// out of order timestamps.  In some cases the timestamps may be milliseconds or seconds out of order.
	// Don't let the clock go backwards as a result:
	if this.lastUnixNano > packetUnixNano {
		glog.Warningf("Backwards timestamp.  cur : %v, last : %v, diff : %d\n", packetUnixNano, this.lastUnixNano, (this.lastUnixNano - packetUnixNano))
		packetUnixNano = this.lastUnixNano
	} else {
		this.lastUnixNano = packetUnixNano
	}

	atomic.StoreInt64(&this.unixNano, packetUnixNano)

	glog.V(2).Infof("sending to reassembly : %v\n", packetUnixNano)

	// now chain to the "super"
	this.ReaderStream.Reassembled(reassembly)
}

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	rat            readerAndTime
}

// A new stream has been found in the pcap
// assembly calls us and we will start a req or resp runner to handle requests or responses
// from this stream.
func (this *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		rat: readerAndTime{
			ReaderStream:   tcpreader.NewReaderStream(),
			pcapStreamSide: make(chan RunnerType),
		},
	}
	hstream.rat.LossErrors = true // Make the reader report stream errors so we abort streams with dropped packets

	hstream.rat.key = &netKey{net, transport}

	numStreams++
	pcapNetReqRespMap[*hstream.rat.key] = numStreams

	// kick off the goroutine runner.  Reassembled() will figure out the side once the first packet gets assembled.
	readWaitGroup.Add(1)
	go hstream.run(numStreams, &numConcurrentStreams)

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.rat
}

type myReader struct {
	*bytes.Buffer
}

func (m myReader) Close() error { return nil }

// Given a timestamp from the pcap file, returns how far
// ahead off wall clock time the filetime.
// Note: takes into account the rate factor.
func timeAheadOfWall(filetime int64, wall time.Time, recnum uint64) (ahead float64, sdiff float64, wdiff float64) {

	// If we are forcing the rate, then we ignore the filetime and
	// substitute the forced rate:
	if *forceRate != 0.0 {
		sdiff = float64(recnum) / *forceRate
	} else {
		sdiff = float64(filetime-firstTimestampUnixNano) / float64(time.Second)
	}

	wdiff = wall.Sub(replayStartTime).Seconds() * *clockrate

	ahead = (sdiff - wdiff) / *clockrate // (sdiff - wdiff) gives time ahead in ajusted rate.  div/rate to give realtime

	return
}

// Given a timestamp from the pcap file, returns how far
// ahead off wall clock time the filetime.
// Note: takes into account the rate factor.
func timeAhead(filetime int64, recnum uint64) (ahead float64, sdiff float64, wdiff float64) {
	return timeAheadOfWall(filetime, time.Now(), recnum)
}

func sleepUntilTimeToSend(timestamp int64, recnum uint64) (sdiffString string) {
	atomic.AddUint64(&numProxySleeping, 1)
	defer atomic.AddUint64(&numProxySleeping, ^uint64(0)) // decrement

	before := time.Now()

	aheadTime, sdiff, wdiff := timeAheadOfWall(timestamp, before, recnum)

	sdiffString = fmt.Sprintf("%f", sdiff)

	// sleep until we are at wall time to send
	if aheadTime > 0 {
		glog.V(2).Infof("sleeping  : %4.6f seconds\n", aheadTime)
		time.Sleep(time.Duration(int64((aheadTime * float64(time.Second)))))

		if *maxInaccuracy > 0.0 {
			after := time.Now()
			if at, _, _ := timeAheadOfWall(timestamp, after, recnum); at < -(*maxInaccuracy) {
				glog.Fatalf("slept too long : %f : %f (before: %v, after: %v)\n", at, aheadTime, before, after)
			}
		}
	} else {
		if *maxInaccuracy > 0.0 {
			if aheadTime < -(*maxInaccuracy) {
				glog.Fatalf("too late already : %f : %f, %f (now: %v, ft: %v, st: %v)\n", aheadTime, sdiff, wdiff, before, timestamp, replayStartTime)
			}
		}
		glog.V(2).Infof("behind by : %4.6f seconds.  sdiff : %4.6f  wdiff : %4.6f\n", aheadTime, sdiff, wdiff)
	}

	return
}

type rlwStuff struct {
	nextWarning time.Time
	numSkipped  int
}

var rlwHash = make(map[string]*rlwStuff)
var rlwMutex sync.Mutex

func limitWarningf(format string, args ...interface{}) {
	rlwMutex.Lock()
	defer rlwMutex.Unlock()
	now := time.Now()

	if stuff, seen := rlwHash[format]; seen {
		if now.After(stuff.nextWarning) {
			if stuff.numSkipped == 0 {
				glog.Warningf(format, args...)
			} else {
				wstr := fmt.Sprintf(format, args...)
				glog.Warningf("(skipped %d):%s\n", stuff.numSkipped, wstr)
				stuff.numSkipped = 0
			}

			stuff.nextWarning = now.Add(rateLimitWarningsDuration)
		} else {
			stuff.numSkipped++
		}
	} else {
		glog.Warningf(format, args...)
		stuff := rlwStuff{
			nextWarning: now.Add(rateLimitWarningsDuration),
			numSkipped:  0,
		}
		rlwHash[format] = &stuff
	}
}

func testChan(c chan bool) bool {
	select {
	case c <- true:
		return true
	default:
		return false
	}
}

// Goroutine for sending request to the proxy and reading the proxy's reply
// Will sleep until it is time to send the request
func (this *httpStream) proxyRequest(req *http.Request, reqlen int, filetime int64, fileTimeAfterReqBody int64, streamnum uint64, numreqs uint64) {
	defer proxyWaitGroup.Done()

	recnum := atomic.AddUint64(&numProxySent, 1)

	sdiffString := sleepUntilTimeToSend(filetime, recnum)

	// If configured, add our timestamp for stat logging/keeping on the remote side:
	if *addDTQuery {
		queryParms := req.URL.Query()
		queryParms.Add(timestampDiffQueryName, sdiffString)
		req.URL.RawQuery = queryParms.Encode()
	}

	if addToQuery != nil && *addToQuery != "" {
		if req.URL.RawQuery != "" {
			req.URL.RawQuery += "&" + *addToQuery
		} else {
			req.URL.RawQuery += *addToQuery
		}
	}

	var before time.Time
	if !testChan(inflightChan) {
		limitWarningf("WARNING: too many inflight : %d.  Waiting until < %d", atomic.LoadUint64(&numProxyInFlight), *maxInflight)

		inflightChan <- true

		before = time.Now()

		// NOTE: we only drop when delay is from max conn limitiation:
		if *dropLaterThan > 0.0 {
			if at, _, _ := timeAheadOfWall(filetime, before, recnum); at < -(*dropLaterThan) {
				limitWarningf("WARNING: dropping late request : %f", at)

				atomic.AddUint64(&numLateDropped, 1)

				droppedRepChan <- &reqinfo{
					URL:          req.URL.Path,
					TS:           fileTimeAfterReqBody,
					ReqLen:       reqlen,
					TimeAccuracy: at,
					streamNum:    streamnum,
					reqNum:       numreqs,
				}

				// Don't forget to clear the inflight.  Can't defer it as it needs to be done before pending on the pcap result
				<-inflightChan

				return
			}
		}

	} else {
		before = time.Now()
	}

	atomic.AddUint64(&numProxyInFlight, 1)

	var resp *http.Response
	var err error

	// clear these out of the header as they will cause RTT to not decode the response properly:
	req.Header.Del("Accept-Encoding")
	req.Header.Del("Range")

	if !*noSend {
		resp, err = roundTripTransport.RoundTrip(req)
	} else {
		err = nil
	}

	// Don't forget to clear the inflight.  Can't defer it as it needs to be done before pending on the pcap result
	<-inflightChan
	atomic.AddUint64(&numProxyInFlight, ^uint64(0)) // decrement

	if err == nil {
		var respCaps []string
		var discarded int
		var respError error
		if !*noSend {

			// Either process the response with a regex capture, or discard it entirely:
			if reRespCapture != nil || *grabTheWholeResponse {
				buf := new(bytes.Buffer)
				numRead, err := buf.ReadFrom(resp.Body)
				discarded = int(numRead)
				// ReadFrom returns nil for EOF.  We need to convert it back:
				if err == nil {
					respError = io.EOF
				} else {
					respError = err
				}
				var respString string
				respString = buf.String()

				if *grabTheWholeResponse {
					respCaps = make([]string, 1)
					respCaps[0] = respString
				} else {
					cap := reRespCapture.FindStringSubmatch(respString)
					if len(cap) > 1 {
						// First pos = entire string
						respCaps = cap[1:]
					}
				}
			} else {
				discarded, respError = tcpreader.DiscardBytesToFirstError(resp.Body)
			}

			if respError != io.EOF {
				glog.Warningf("WARNING: got error reading response for req : %v.  Error : %v\n", req, respError)
				statRepChan <- nil

				return
			}
		} else {
			discarded = 0
		}

		// Note that we need to take after time after reading the body
		// as httpClient.Do may return before the response body is read
		// from the wire
		after := time.Now()

		var rc int
		if !*noSend {
			rc = resp.StatusCode
			resp.Body.Close()
		}

		accuracy, _, wallDiff := timeAheadOfWall(filetime, before, recnum)

		var eparms []string
		if getParmsList != nil && len(getParmsList) != 0 {
			eparms = make([]string, len(getParmsList), len(getParmsList))
		}

		for i, parm := range getParmsList {
			eparms[i] = req.URL.Query().Get(parm)
		}

		var urlString string
		if *grabTheWholeURL {
			urlString = req.URL.String()
		} else {
			urlString = req.URL.Path
		}

		//  Report back stats:
		statRepChan <- &stat{
			reqinfo: reqinfo{
				URL:          urlString,
				TS:           filetime,
				wallDiff:     wallDiff,
				ReqLen:       reqlen,
				TimeAccuracy: accuracy,
				streamNum:    streamnum,
				reqNum:       numreqs,
				getParms:     eparms,
			},
			RTT:       after.Sub(before).Seconds(),
			RespLen:   discarded,
			RC:        rc,
			respMatch: respCaps,
		}

	} else {
		glog.Warningf("WARNING: got error sending request : %s : %v\n", req.URL.String(), err)
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		statRepChan <- nil
	}

}

// Goroutine for ignoring stream:
func (this *httpStream) ignoreAndThrowAway() {
	defer readWaitGroup.Done()

	discarded := tcpreader.DiscardBytesToEOF(&this.rat)
	glog.V(2).Infof("ignoreAndThrowAway() : throwing away stream.  Discarded %d bytes\n", discarded)
}

// Goroutine for handling pcap data for an individual TCP stream in the request direction
func (this *httpStream) reqRun(streamNum uint64, counter *uint64) {
	defer readWaitGroup.Done()

	glog.V(2).Infof("reqRun: starting streamNum : %d.  %v : %v ft: %v\n", streamNum, this.net, this.transport, time.Unix(0, atomic.LoadInt64(&this.rat.unixNano)))

	cur := atomic.AddUint64(counter, 1)
	if cur > concurrentStreamHWM {
		concurrentStreamHWM = cur
	}
	defer func() {
		// Decrement counter:
		atomic.AddUint64(counter, ^uint64(0))
	}()

	buf := bufio.NewReader(&this.rat)
	for numreqs := uint64(0); ; /* forever */ {
		// Make sure to count us as pending on stream data when we read:
		atomic.AddUint64(&streamWaitingOnData, 1)
		req, err := http.ReadRequest(buf)
		atomic.AddUint64(&streamWaitingOnData, ^uint64(0)) // Decrement

		glog.V(2).Infof("reqRun: read :request header from streamnum: %d.  nr:%d.  err: %v\n", streamNum, numreqs, err)

		// NOTE: we *have* a race here.  Another goroutine has updated this.rat.unixNano
		//       we are loading it.  It may be that the main goroutine has already read the
		//       next packet from the stream, and we are loading the future packet's timestamp.
		//       In that case we will send our request late, but all else should be OK.
		packetTimestampUnixNano := atomic.LoadInt64(&this.rat.unixNano)
		nowUnixNano := time.Now().UnixNano()

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// done with this http tcp stream.

			if numreqs == 0 {
				glog.V(2).Infoln("http connection closed normally with no data.")
			}
			return
		} else if err != nil {
			// Make sure to count us as pending on stream data while we read to discard:
			atomic.AddUint64(&streamWaitingOnData, 1)
			discarded := tcpreader.DiscardBytesToEOF(buf)
			atomic.AddUint64(&streamWaitingOnData, ^uint64(0)) // Decrement

			glog.V(1).Infof("Error reading request stream from pcap.  Discarded %d. %v : %v : %v\n", discarded, this.net, this.transport, err)
			atomic.AddUint64(&numPcapReqErrs, 1)
			return
		} else {
			// Are we even too late before now?
			if *maxInaccuracy > 0.0 {
				if aheadTime, sdiff, wdiff := timeAhead(packetTimestampUnixNano, atomic.LoadUint64(&numProxySent)); aheadTime < -(*maxInaccuracy) {
					glog.Fatalf("too late already before even reading body : %f : %f, %f (ft: %d, nun : %d, st: %d)\n",
						aheadTime, sdiff, wdiff, packetTimestampUnixNano, nowUnixNano, replayStartTime.UnixNano())
				}
			}

			// We need to copy data into a new request, waiting until all bytes from the
			// original request are available to put into the new request.
			// Then we'll launch the replay in its own goroutine.  But we can not launch
			// the new goroutine until we have all the data for the request.
			atomic.AddUint64(&streamWaitingOnData, 1) // Count us as pending on stream data while we read body
			bodyBytes, err := ioutil.ReadAll(req.Body)
			atomic.AddUint64(&streamWaitingOnData, ^uint64(0)) // Decrement

			fileTimeAfterReqBody := atomic.LoadInt64(&this.rat.unixNano)

			if err != nil {
				discarded := tcpreader.DiscardBytesToEOF(buf)
				glog.V(1).Infof("Error reading body from stream %v : %v : %v.  Discarded : %d\n", this.net, this.transport, err, discarded)
				atomic.AddUint64(&numPcapReqErrs, 1)
				return
			}
			req.Body.Close()

			reqlen := len(bodyBytes)

			glog.V(2).Infof("reqRun: read :%d bytes from streamnum: %d : %v\n", reqlen, streamNum, time.Unix(0, fileTimeAfterReqBody))
			// If we are filtering, filter out here:
			if reReqURLs == nil || reReqURLs.MatchString(req.URL.String()) {
				newBody := myReader{bytes.NewBuffer(bodyBytes)}

				req.Body = newBody

				// force the scheme and host to our proxyURL
				req.URL.Scheme = proxyURL.Scheme
				req.URL.Host = proxyURL.Host
				if *overrideHost != "" {
					req.Host = *overrideHost
				}

				// force req to close tcp socket (not persist) once response received:
				req.Close = true

				numreqs++
				atomic.AddUint64(&totNumReqs, 1)

				if numreqs > atomic.LoadUint64(&reqPerStreamHWM) {
					atomic.StoreUint64(&reqPerStreamHWM, numreqs)
				}

				// Are we even too late before now?
				if *maxInaccuracy > 0.0 {
					if aheadTime, sdiff, wdiff := timeAhead(packetTimestampUnixNano, atomic.LoadUint64(&numProxySent)); aheadTime < -(*maxInaccuracy) {
						glog.Fatalf("too late already before go ProxyRequest : %f : %f, %f (ft: %d, st: %d)\n",
							aheadTime, sdiff, wdiff, packetTimestampUnixNano, replayStartTime.UnixNano())
					}
				}

				proxyWaitGroup.Add(1)
				go this.proxyRequest(req, reqlen, packetTimestampUnixNano, fileTimeAfterReqBody, streamNum, numreqs)
			}
		}
	}
}

// Goroutine for handling pcap data for an individual TCP stream in the response direction
func (this *httpStream) respRun(streamNum uint64, counter *uint64) {
	defer readWaitGroup.Done()
	glog.V(2).Infof("respRun: starting streamNum : %d.  %v : %v ft: %v\n", streamNum, this.net, this.transport, time.Unix(0, atomic.LoadInt64(&this.rat.unixNano)))

	buf := bufio.NewReader(&this.rat)
	for numresps := uint64(0); ; /* forever */ {
		// Make sure to count us as pending on stream data when we read:
		atomic.AddUint64(&streamWaitingOnData, 1)
		resp, err := http.ReadResponse(buf, nil)
		atomic.AddUint64(&streamWaitingOnData, ^uint64(0)) // Decrement

		glog.V(2).Infof("respRun: read :response header from streamnum: %d.  nr:%d.  err: %v\n", streamNum, numresps, err)

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// done with this http tcp stream.

			if numresps == 0 {
				glog.V(2).Infoln("http connection closed normally with no resp data.")
				return
			}

			return
		} else if err != nil {
			// Make sure to count us as pending on stream data while we read to discard:
			atomic.AddUint64(&streamWaitingOnData, 1)
			discarded := tcpreader.DiscardBytesToEOF(buf)
			atomic.AddUint64(&streamWaitingOnData, ^uint64(0)) // Decrement

			glog.V(1).Infof("Error reading resp stream from pcap.  Discarded %d. %v : %v : %v\n", discarded, this.net, this.transport, err)
			atomic.AddUint64(&numPcapRespErrs, 1)
			return
		} else {
			numresps++

			glog.V(2).Infof("respRun: read :response header from streamnum: %d.  len : %d, status : %s, code : %d, header : %v\n",
				streamNum, resp.ContentLength, resp.Status, resp.StatusCode, resp.Header)

			bodyBytes, err := ioutil.ReadAll(resp.Body)

			if err != nil {
				discarded := tcpreader.DiscardBytesToEOF(buf)
				glog.V(1).Infof("Error reading resp body from pcap stream.  Discarded %d.  %v", discarded, err)
				atomic.AddUint64(&numPcapRespErrs, 1)
				return
			}

			// Wait until all the body's been read to get the time
			latestPcapTime := atomic.LoadInt64(&this.rat.unixNano)

			glog.V(2).Infof("respRun: read :%d bytes from streamnum: %d. ft: %v", len(bodyBytes), streamNum, time.Unix(0, latestPcapTime))

			pcapRespRepChan <- &pcapRespinfo{
				Resptime:      latestPcapTime,
				OrigRC:        resp.StatusCode,
				OrigRlen:      len(bodyBytes),
				respStreamNum: streamNum,
				respNum:       numresps,
			}

		}
	}
}

// Assmebly runner handles stream data that will arrive on this.rat from Reassembly.
// Note: must guarantee reading of rat when data is pending or deadlock will ensue.
func (this *httpStream) run(streamNum uint64, counter *uint64) {
	glog.V(2).Infof("Starting assembly runner for stream %d rat: %v\n", streamNum, this.rat)

	// We have been dispatched, but still don't know what side we're on.
	// The first packet seen on the stream may not be SYN - it could (in theory)
	// arrive out of order, or otherwise be out of order in the pcap.  However by
	// the time data comes to us in strict mode from Reassembled() we will have our
	// SYN.  We'll wait here until Reassembled() sends us our side:
	if side := <-this.rat.pcapStreamSide; side == Error {
		this.ignoreAndThrowAway()
	} else if side == Request {
		// Client side is a request stream:
		this.reqRun(streamNum, counter)
	} else {
		// Server side is a response stream.

		// Find the request stream number:
		revkey := *this.rat.key.Reverse()

		// TODO: pcapNetReqRespMap probably needs to be protected as its written in main's context and read in this goroutine's context
		if reqStreamNum, is := pcapNetReqRespMap[revkey]; is {
			// we're done needing these keys.  Save us some memory:
			delete(pcapNetReqRespMap, revkey)
			delete(pcapNetReqRespMap, *this.rat.key)

			this.respRun(reqStreamNum, counter)
		} else {
			glog.V(1).Infof("Unmatched response encountered %v:%v.  Throwing Away.",
				this.rat.key.net, this.rat.key.transport)
			this.ignoreAndThrowAway()
		}
	}
}

var rtts = make([]float64, 0, 10000000) // 10 million initial length

// log the stat if logging is enabled.  Also keep track of failed results
func handleStat(someStat *stat, logStats bool, statLog *log.Logger, stated int, failed int) (int, int) {
	if someStat != nil {
		rtts = append(rtts, someStat.RTT)
		stated++

		if logStats {
			statLog.Println(someStat.String())
		}
	} else {
		failed++
	}

	return stated, failed
}

// goroutine to handle reporting from proxy goroutines
func reporting(done chan bool) {

	logStats := false
	var statfile *os.File
	if *statOutfile != "" {
		logStats = true

		var err error
		if statfile, err = os.Create(*statOutfile); err != nil {
			glog.Fatalf("Failed to open stat output file %s : %v\n", *statOutfile, err)
		}
	}
	statLog := log.New(statfile, "", 0)

	logDropped := false
	var droppedfile *os.File
	if *droppedOutfile != "" {
		logDropped = true

		var err error
		if droppedfile, err = os.Create(*droppedOutfile); err != nil {
			glog.Fatalf("Failed to open dropped output file %s : %v\n", *droppedOutfile, err)
		}
	}
	droppedLog := log.New(droppedfile, "", 0)

	tensecs := time.Tick(time.Second * 10)

	stated := 0
	failed := 0
	dropped := 0
	lastStated := 0
	numMismatchedRCs := 0

	lastTime := time.Now()
	finishingUp := false
	for {
		select {
		case someStat := <-statRepChan:
			if *readResponse && someStat != nil {
				// do we have the other side?
				key := streamKey{someStat.streamNum, someStat.reqNum}
				if presp, is := streamRespSeqMap[key]; is {
					delete(streamRespSeqMap, key)

					presp.OrigRTT = float64(presp.Resptime-someStat.TS) / float64(time.Second)
					someStat.pcapRespinfo = *presp
					stated, failed = handleStat(someStat, logStats, statLog, stated, failed)
					if someStat.OrigRC != someStat.RC {
						numMismatchedRCs++
					}
				} else {
					streamReqSeqMap[key] = someStat
				}
			} else {
				stated, failed = handleStat(someStat, logStats, statLog, stated, failed)
			}

		case someDrop := <-droppedRepChan:
			dropped++
			if logDropped {
				droppedLog.Println(someDrop.String())
			}

		case somePcapResp := <-pcapRespRepChan:
			// do we have the other side?
			if somePcapResp != nil {
				key := streamKey{somePcapResp.respStreamNum, somePcapResp.respNum}
				if reqstat, is := streamReqSeqMap[key]; is {
					delete(streamReqSeqMap, key)
					somePcapResp.OrigRTT = float64(somePcapResp.Resptime-reqstat.TS) / float64(time.Second)
					reqstat.pcapRespinfo = *somePcapResp
					stated, failed = handleStat(reqstat, logStats, statLog, stated, failed)
					if reqstat.OrigRC != reqstat.RC {
						numMismatchedRCs++
					}
				} else {
					streamRespSeqMap[key] = somePcapResp
				}
			}

		case <-tensecs:
			diffStated := stated - lastStated
			lastStated = stated

			now := time.Now()
			rate := float64(diffStated) / now.Sub(lastTime).Seconds()
			lastTime = now

			var repstate string
			if finishingUp {
				repstate = "Finishing Up"
			} else {
				repstate = "Still Running"
			}

			glog.Infof("%s: rate : %f  Reported : %d  Failed : %d.  Flawed : %d.  reqs : %d, proxySent : %d, sleeping : %d, inFlight : %d, lateDropped : %d\n",
				repstate,
				rate,
				stated,
				failed,
				atomic.LoadUint64(&numBadStreams),
				atomic.LoadUint64(&totNumReqs),
				atomic.LoadUint64(&numProxySent),
				atomic.LoadUint64(&numProxySleeping),
				atomic.LoadUint64(&numProxyInFlight),
				atomic.LoadUint64(&numLateDropped))

		case <-done:
			// This is a little ugly, but we need to still process anything left in the statRepChan, but we can't
			// pend on the chan:
			finishingUp = true

		default:
			if finishingUp {
				glog.Infof("Done reporting.  Stated : %d  Failed : %d.  Flawed : %d.  Unmatched reqs: %d.  Unmatched resps: %d.  Pcap req errs : %d, Pcap resp errs : %d\n",
					stated,
					failed,
					atomic.LoadUint64(&numBadStreams),
					len(streamReqSeqMap),
					len(streamRespSeqMap),
					atomic.LoadUint64(&numPcapReqErrs),
					atomic.LoadUint64(&numPcapRespErrs))

				if len(streamReqSeqMap) > 0 {
					// Go through all unmatched reqs and log them without the responses:
					for _, reqStat := range streamReqSeqMap {
						stated, failed = handleStat(reqStat, logStats, statLog, stated, failed)
					}

					glog.Infof("Reported unmatched reqs.  Stated : %d  Failed : %d (sum : %d).\n",
						stated,
						failed,
						stated+failed)
				}

				// Calculate average round trip time and standard deviation
				var avg float64 = 0
				var std float64 = 0
				for _, rtt := range rtts {
					avg += rtt
				}
				if nv := len(rtts); nv != 0 {
					avg = avg / float64(nv)
				}

				for _, rtt := range rtts {
					diff := avg - rtt
					std += diff * diff
				}
				if nv := len(rtts); nv != 0 {
					std = std / float64(nv)
				}

				numRespStated := stated - len(streamReqSeqMap)
				// prevent DVZ
				if numRespStated == 0 {
					numRespStated = -1
				}

				smryString := fmt.Sprintf("Stated : %d  Failed : %d.  Flawed Streams: %d.  Mismatched RCs: %d (%3.3f%%).  Avg RTT %f sdev : %f.  Unmatched reqs: %d.  Unmatched resps : %d.  Flawed Reqs : %d.  Flawed Resps : %d.  Dropped : %d Pcap req errs : %d, Pcap resp errs : %d",
					stated,
					failed,
					numBadStreams,
					numMismatchedRCs,
					100*float64(numMismatchedRCs)/float64(numRespStated),
					avg,
					std,
					len(streamReqSeqMap),
					len(streamRespSeqMap),
					flawedReqStreams,
					flawedRespStreams,
					dropped,
					atomic.LoadUint64(&numPcapReqErrs),
					atomic.LoadUint64(&numPcapRespErrs))

				glog.Infof("Summary : %s\n", smryString)

				if logStats {
					statLog.Printf("# Summary:\n")
					statLog.Printf("# %s\n", smryString)
				}

				statfile.Close()

				done <- true
				return
			}
		}
	}
}

// Send an HTTP get to the proxy that will instruct the proxy to zero its timestamp counter.
// Used at the begining of a test so that the proxy can report data since the test start.
func sendProxyInitTC(u url.URL) (resp *http.Response, err error) {
	queryParms := u.Query()
	queryParms.Add(timestampDiffQueryName, "-1")
	u.RawQuery = queryParms.Encode()
	return http.Get(u.String())
}

// Main
func main() {
	flag.Var(&getParmsList, "extraParm", "Get Paramater to record in output")
	flag.Parse()

	// Compile regex for req URL filtering (if passed in)
	if filterReqURLs != nil && *filterReqURLs != "" {
		reReqURLs = regexp.MustCompile(*filterReqURLs)
		glog.V(2).Infof("Set reReqURLs to re for %s\n", *filterReqURLs)
	}

	// Compile regex for response capture (if passed in)
	if respCaptureString != nil && *respCaptureString != "" {
		reRespCapture = regexp.MustCompile(*respCaptureString)
		glog.V(2).Infof("Set reRespCapture to re for %s\n", *respCaptureString)
	}

	if pcapFilename == nil || *pcapFilename == "" {
		glog.Fatal("please provide a pcap filename.")
	}

	var rlwError error
	rateLimitWarningsDuration, rlwError = time.ParseDuration(*rateLimitWarnings)
	if rlwError != nil {
		glog.Fatalf("Invalid rate limit for warnings : %s\n", *rateLimitWarnings)
	}

	// We are going to open our pcap twice.  Once here just to grab the first timestamp
	// But once we have the first packet, we can't put it back, so we'll abandon the file
	// and start over:
	if handle, err := pcap.OpenOffline(*pcapFilename); err != nil {
		glog.Fatalf("Error opening %s : %v\n", *pcapFilename, err)
	} else {
		_, ci, err := handle.ReadPacketData()
		if err != nil {
			glog.Fatalf("Error reading first packet from %s\n", *pcapFilename)
		}
		firstPcapTimestamp = ci.Timestamp
		firstTimestampUnixNano = firstPcapTimestamp.UnixNano()
		handle.Close()
	}

	handle, err := pcap.OpenOffline(*pcapFilename)
	if err != nil {
		glog.Fatalf("Error opening %s even though it opened ok before : %v\n", *pcapFilename, err)
	}

	if err := handle.SetBPFFilter(*capFilt); err != nil {
		glog.Fatalf("Error setting capture filter %s : %v\n", *capFilt, err)
	}

	if proxyURL, err = url.Parse(*serverURL); err != nil {
		glog.Fatalf("Invalid server URL %v\n", err)
	}

	maxprocs := runtime.GOMAXPROCS(-1) // query gomaxprocs
	glog.Infof("GOMAXPROCS : %d\n", maxprocs)

	replayStartTime = time.Now()

	// If we are going to force the rate, make sure clockrate is set to 1.0:
	if *forceRate != 0.0 {
		*clockrate = 1.0
	}

	// Set up packet re-assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetsChan := packetSource.Packets()

	secondChan := time.Tick(time.Second)

	statRepChan = make(chan *stat, 1024) // don't block proxys waiting to report stats
	pcapRespRepChan = make(chan *pcapRespinfo, 1024)
	droppedRepChan = make(chan *reqinfo, 1024)

	inflightChan = make(chan bool, *maxInflight)

	// If configured, let the proxy server know we are starting to zero its timestamp counter:
	if *addDTQuery {
		sendProxyInitTC(*proxyURL)
	}

	var lastPacketFiletimeNano int64 = 0
	doneChan := make(chan bool)
	go reporting(doneChan)
	for sent := 0; ; {
		select {
		case packet := <-packetsChan:

			// Check to see if we're set to exit after a number of requests:
			if *stopAfterNumReqs != 0 && atomic.LoadUint64(&totNumReqs) > *stopAfterNumReqs {
				glog.Infof("Exiting after %d requests. (actual : %d)\n", *stopAfterNumReqs, atomic.LoadUint64(&totNumReqs))
				// Act as if we've hit EOF:
				packet = nil
			}

			if packet != nil {
				numPackets++

				if *dumpPackets {
					fmt.Printf("%d: %v\n", numPackets, packet)
				}
				if packet.NetworkLayer() != nil && packet.TransportLayer() != nil && packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
					curPacketFiletime := packet.Metadata().Timestamp
					curPacketFiletimeNano := curPacketFiletime.UnixNano()

					// check for backwards timestamps (with a few mil tol)
					if lastPacketFiletimeNano > curPacketFiletimeNano {
						if lastPacketFiletimeNano > (curPacketFiletimeNano + 100000000) {
							glog.Infof("MAIN: pcap stamps going backwards : cur : %d, last : %d (%d) (%d)\n", curPacketFiletimeNano, lastPacketFiletimeNano, (curPacketFiletimeNano - lastPacketFiletimeNano), numPackets)
							glog.Fatalf("Bytes:\n'%s'\n", packet.TransportLayer().(*layers.TCP).LayerPayload())
						} else {
							// don't let the filestamps go backwards at all:
							curPacketFiletime = time.Unix(0, lastPacketFiletimeNano)
						}
					} else {
						lastPacketFiletimeNano = curPacketFiletimeNano
					}

					// Don't get too far ahead:
					aheadTime, _, _ := timeAhead(curPacketFiletimeNano, atomic.LoadUint64(&numProxySent))

					if aheadTime > *readAheadTime {
						howFarAhead := aheadTime - *readAheadTime
						if howFarAhead > (*readAheadTime / 10.0) {
							howFarAhead = *readAheadTime / 10.0 // limit how much we'll sleep in one step
						}

						glog.V(2).Infof("ahead of pcap by : %f seconds.  Sleeping %f seconds.", aheadTime, howFarAhead)
						time.Sleep(time.Duration(int64((howFarAhead * float64(time.Second)))))
					}

					sent++
					tcp := packet.TransportLayer().(*layers.TCP)

					// Need to get the current packet to httpStreamFactory New().  Stick it in global curPacket
					// (small hack)
					curPacket = &packet
					assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, curPacketFiletime)
				}
			} else { // End of file
				glog.Infof("Done reading packet capture file.  Flushing connections.  reqs : %d, proxySent : %d, sleeping : %d, inFlight : %d, lateDropped : %d\n",
					atomic.LoadUint64(&totNumReqs),
					atomic.LoadUint64(&numProxySent),
					atomic.LoadUint64(&numProxySleeping),
					atomic.LoadUint64(&numProxyInFlight),
					atomic.LoadUint64(&numLateDropped))

				closed := assembler.FlushAll()
				glog.Infof("Done reading packet capture file.  Sent %d packets.  Closed %d stragler connections.\n",
					numPackets, closed)

				glog.Infof(
					"Waiting for stream reader goroutines to finish.  reqs : %d, proxySent : %d, outstanding : %d\n",
					atomic.LoadUint64(&totNumReqs),
					atomic.LoadUint64(&numProxySent),
					atomic.LoadUint64(&numProxyInFlight))
				readWaitGroup.Wait() // wait for all stream reader goroutines to finish

				glog.Infof("Waiting for proxy goroutines to finishreqs : %d, proxySent : %d, outstanding : %d\n",
					atomic.LoadUint64(&totNumReqs),
					atomic.LoadUint64(&numProxySent),
					atomic.LoadUint64(&numProxyInFlight))
				proxyWaitGroup.Wait() // wait for

				glog.Infof("Wrapping up.  reqs : %d, proxySent : %d, outstanding : %d\n",
					atomic.LoadUint64(&totNumReqs),
					atomic.LoadUint64(&numProxySent),
					atomic.LoadUint64(&numProxyInFlight))

				// tell reporter we're done:
				doneChan <- true
				// and wait for it to be done:
				<-doneChan

				elapsed := time.Now().Sub(replayStartTime)
				glog.Infof("number of connections with lost packets causing data loss: %d\n", numFlushed)
				glog.Infof("number of connections with abnormal termination: %d\n", numClosed)
				glog.Infof("max number of simultaneous concurrant streams : %d\n", concurrentStreamHWM)
				glog.Infof("elapsed : %v, rate : %f, reqs : %d, streams : %d, reqs/stream : %f avg (%d hwm)\n",
					elapsed,
					float64(totNumReqs)/elapsed.Seconds(),
					totNumReqs, numStreams, float64(totNumReqs)/float64(numStreams), reqPerStreamHWM)

				glog.Flush()
				return
			}

		case <-secondChan:
			// Wake up every second and flush anything stale:
			assembler.FlushOlderThan(time.Now().Add(time.Duration(-1.0 * *flushPeriod * float64(time.Second))))
		}
	}
}
