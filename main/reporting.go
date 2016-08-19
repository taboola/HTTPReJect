package main

import (
	"log"
	"os"
	"github.com/golang/glog"
	"time"
	"sync/atomic"
	"fmt"
	"bytes"
)

// Note that even though we do perform atomic operations on stopCalled, since it is an int32 we do not require it
// to be on an 8-byte aligned address (see class doc of doc.go - atomic operations)
// It currently does happen to be 8-byte aligned, but that is just a coincidence, and again, is irrelevant.
type reporter struct  {
	failed                         int
	stated                         int
	dropped			       int
	rtts                           []float64 //history of round trip times
	numMismatchedRCs	       int

	logStats                       bool
	logDropped                     bool
	expectResponses                bool

	statsLogPath                   string
	droppedLogPath                 string

	initiatedChannel               chan bool //channel through which we signal that the initialization has completed.
	requestToFinishChannel         chan bool
	notifyFinishedChannel          chan bool //channel through which we signal to clients that finishing is done.
	requestReportingChannel        chan *stat
	responseReportingChannel       chan *pcapRespinfo
	droppedRequestReportingChannel chan *reqinfo
	failedRequestsReportingChannel chan bool


	log                            *log.Logger
	droppedLog                     *log.Logger
}

func NewReporter(expectResponses bool, statsLogPath string, droppedLogPath string) *reporter {

	var rep *reporter = new(reporter)
	rep.statsLogPath = statsLogPath
	rep.droppedLogPath = droppedLogPath
	rep.rtts = make([]float64, 0, 10000000)

	rep.logStats = statsLogPath != ""
	rep.logDropped = droppedLogPath != ""

	rep.initiatedChannel = make(chan bool, 1)
	rep.notifyFinishedChannel = make(chan bool, 1)
	rep.requestToFinishChannel = make(chan bool, 1024)
	rep.requestReportingChannel = make(chan *stat, 1024) // don't block proxys waiting to report stats
	rep.responseReportingChannel = make(chan *pcapRespinfo, 1024)
	rep.droppedRequestReportingChannel = make(chan *reqinfo, 1024)
	rep.failedRequestsReportingChannel = make(chan bool, 1024)

	return rep
}

type stat struct {
	reqinfo
	pcapRespinfo
	RTT       float64  // Round Trip Time
	RC        int      // Return Code
	RespLen   int      // Response length
	respMatch []string // matching captures from the response
}

func join(strings []string, delimiter byte) string {

	var buffer bytes.Buffer //this may be an allocation bottleneck - watch out
	if (strings == nil || len(strings) == 0) {
		return ""
	} else {
		for i,s := range strings {
			buffer.WriteString(s)
			if i < len(strings) - 1 {
				buffer.WriteByte(delimiter)
			}
		}
	}

	return buffer.String()
}

// wait until all initialization has been performed by the reporter
// note that this does *not* mean that the reporter has entered the select-clause!
// it only means that all initialization is done. This should be used to prevent race conditions
// by calling this function *before* closing the reporter, from within the *same* goroutine.
// example code:
//
// 	func foo(rep *reporter) {
//		go rep.Report()
//		rep.ReportDropped(...)
//		rep.AwaitInitialization()
//		rep.Stop()
//		rep.SyncFlush()
//	}
//
// Note that in the example, we perform the actual reporting actions (in this case reporting a dropped request)
// before calling this method. Calling this method before reporting will not guarantee that initialization had been finished
// and in fact, there is no reason (currently) to require such a mechanism.
//
// As to the implementation, since initiatedChannel is a buffered channel of size 1, more should
// be false any time it is received from. It is only required since this function may be called from
// many different clients, in which case sampling the channel would have no effect since it is already closed (except
// for the one client who receives the message).
func (this *reporter) AwaitInitialization() {
	if _, more := <- this.initiatedChannel; !more {
		return
	}

}

//Signals the reporter to stop reporting,
//once all previously delivered stats have been handled.
//stats which have been submitted after calling Stop() may also be handled,
//but there is no guarantee that this will happen and how many of them will be handled.
func (this *reporter) Stop() {
	this.requestToFinishChannel <- true
}

//wait until all stats which were submitted before calling Stop() have been handled.
//this function may return after some stats have been handled which were submitted after Stop() was called -
//see Stop's docs.
//calling this function before calling Stop() will result in no wait being performed,
//instead an error being immediately returned
func (this *reporter) SyncFlush() {
	if _, more := <- this.notifyFinishedChannel; !more {
		//continue...
	}
}

func (this *reporter) ReportDropped(droppedRequestInfo *reqinfo) {
	this.droppedRequestReportingChannel <-	droppedRequestInfo
}

func (this *reporter) ReportStat(requestStats *stat) {
	this.requestReportingChannel <- requestStats
}

func (this *reporter) ReportFailedStat() {
	this.failedRequestsReportingChannel <- true
}

func (this *reporter) ReportResponse(responseInfo *pcapRespinfo) {
	this.responseReportingChannel <- responseInfo
}

func (this *stat) String() string {

	extraParms := join(this.getParms, ',')
	respMatches := join(this.respMatch, ',')

	return fmt.Sprintf("%v,%s,%03d,%f,%d,%d,%f,%d,%d,%d,%03d,%f,%f%s%s",
		time.Unix(0, this.TS), this.URL, this.RC, this.RTT, this.ReqLen, this.RespLen, this.TimeAccuracy, this.streamNum,
		this.reqNum, this.OrigRlen, this.OrigRC, this.OrigRTT, this.wallDiff, extraParms, respMatches)
}


func (this *reporter) addFailedStat() {
	this.failed++
}

// log the stat if logging is enabled.  Also keep track of failed results
func (this *reporter) AddStat(someStat *stat) {
	if someStat != nil {
		this.rtts = append(this.rtts, someStat.RTT)
		this.stated++

		if this.logStats {
			this.log.Println(someStat.String())
		}
	}
}

// goroutine to handle reporting from proxy goroutines
func (this *reporter) Report () {

	var statfile *os.File
	if this.logStats {
		var err error
		if statfile, err = os.Create(this.statsLogPath); err != nil {
			glog.Fatalf("Failed to open stat output file %s : %v\n", this.statsLogPath, err)
		}
	}
	this.log = log.New(statfile, "", 0)

	var droppedfile *os.File
	if this.logDropped {
		var err error
		if droppedfile, err = os.Create(this.droppedLogPath); err != nil {
			glog.Fatalf("Failed to open dropped output file %s : %v\n", this.droppedLogPath, err)
		}
	}
	this.droppedLog = log.New(droppedfile, "", 0)

	tensecs := time.Tick(time.Second * 10)

	lastStated := 0 //amount of recorded stats for which last calculation of rate was performed

	lastTime := time.Now() //last measured time by which we perform rate calculation
	this.initiatedChannel <- true

	glog.Info("Before select")
	for {
		select {
		case someStat := <- this.requestReportingChannel:
			this.handleRequestStat(someStat)

		case someDrop := <- this.droppedRequestReportingChannel:
			this.handleDroppedStat(someDrop)

		case somePcapResp := <- this.responseReportingChannel:
			this.handleResponseStat(somePcapResp)

		case <-this.failedRequestsReportingChannel:
			this.addFailedStat()

		case <-tensecs:

			// calculate rate of handled requests/responses and update state counters (lastStated & lastTime)
			// for the next calculation
			diffStated := this.stated - lastStated
			lastStated = this.stated
			now := time.Now()
			rate := float64(diffStated) / now.Sub(lastTime).Seconds()
			lastTime = now

			//var repstate string
			//if finishingUp {
			//	repstate = "Finishing Up"
			//} else {
			//	repstate = "Still Running"
			//}

			//glog.Infof("%s: rate : %f  Reported : %d  Failed : %d.  Flawed : %d.  reqs : %d, proxySent : %d, sleeping : %d, inFlight : %d, lateDropped : %d\n",
			glog.Infof("rate : %f  Reported : %d  Failed : %d.  Flawed : %d.  reqs : %d, proxySent : %d, sleeping : %d, inFlight : %d, lateDropped : %d\n",
				//repstate,
				rate,
				this.stated,
				this.failed,
				atomic.LoadUint64(&numBadStreams),
				atomic.LoadUint64(&totNumReqs),
				atomic.LoadUint64(&numProxySent),
				atomic.LoadUint64(&numProxySleeping),
				atomic.LoadUint64(&numProxyInFlight),
				atomic.LoadUint64(&numLateDropped))

		case <-this.requestToFinishChannel:
			glog.Info("Got done notification, emptying rest of data")
			finishedEmptying := false
			for !finishedEmptying {
				select {
				case someStat := <- this.requestReportingChannel:
					this.handleRequestStat(someStat)

				case someDrop := <- this.droppedRequestReportingChannel:
					this.handleDroppedStat(someDrop)

				case somePcapResp := <- this.responseReportingChannel:
					this.handleResponseStat(somePcapResp)

				case <-this.failedRequestsReportingChannel:
					this.addFailedStat()

				default:
					//exit
					finishedEmptying = true
				}
			}

			glog.Info("After emptying rest of data, printing")
			this.finish(statfile, droppedfile)
			this.notifyFinishedChannel <- true
		}
	}
}

// returns whether the incoming stat had a mismatched return code
func (this *reporter) handleRequestStat(someStat *stat) {
	glog.Info("Received stat")

	if this.expectResponses && someStat != nil {
		// do we have the other side?
		key := streamKey{someStat.streamNum, someStat.reqNum}
		if presp, is := streamRespSeqMap[key]; is {
			delete(streamRespSeqMap, key)

			presp.OrigRTT = float64(presp.Resptime-someStat.TS) / float64(time.Second)
			someStat.pcapRespinfo = *presp
			this.AddStat(someStat)
			if someStat.OrigRC != someStat.RC {
				this.numMismatchedRCs++
			}
		} else {
			streamReqSeqMap[key] = someStat
		}
	} else {
		this.AddStat(someStat)
	}
}

func (this *reporter) handleDroppedStat(req *reqinfo) {
	glog.Info("Got dropped")
	this.dropped++
	if this.logDropped {
		this.droppedLog.Println(req.String())
	}
}

func (this *reporter) handleResponseStat(somePcapResp *pcapRespinfo) {
	glog.Info("Got response")
	// do we have the other side?
	if somePcapResp != nil {
		key := streamKey{somePcapResp.respStreamNum, somePcapResp.respNum}
		if reqstat, is := streamReqSeqMap[key]; is {
			delete(streamReqSeqMap, key)
			somePcapResp.OrigRTT = float64(somePcapResp.Resptime-reqstat.TS) / float64(time.Second)
			reqstat.pcapRespinfo = *somePcapResp
			this.AddStat(reqstat)
			if reqstat.OrigRC != reqstat.RC {
				this.numMismatchedRCs++
			}
		} else {
			streamRespSeqMap[key] = somePcapResp
		}
	}
}

func (this *reporter) finish(statFile *os.File, droppedFile *os.File) {
	glog.Info("Finishing")
	glog.Infof("Done reporting.  Stated : %d  Failed : %d.  Flawed : %d.  Unmatched reqs: %d.  Unmatched resps: %d.  Pcap req errs : %d, Pcap resp errs : %d\n",
		this.stated,
		this.failed,
		atomic.LoadUint64(&numBadStreams),
		len(streamReqSeqMap),
		len(streamRespSeqMap),
		atomic.LoadUint64(&numPcapReqErrs),
		atomic.LoadUint64(&numPcapRespErrs))

	if len(streamReqSeqMap) > 0 {
		// Go through all unmatched reqs and log them without the responses:
		for _, reqStat := range streamReqSeqMap {
			this.AddStat(reqStat)
		}

		glog.Infof("Reported unmatched reqs.  Stated : %d  Failed : %d (sum : %d).\n",
			this.stated,
			this.failed,
			this.stated+this.failed)
	}

	// Calculate average round trip time and standard deviation
	// It seems recording a histogram would be better fit here, since we're dealing with latencies.
	// Consider using go port of HdrHistogram? This would also save up on memory, since
	// right now we are recording *every* rtt, while the histogram is fixed-size
	avg, std := summarize(this.rtts)

	numRespStated := this.stated - len(streamReqSeqMap)
	// prevent DVZ
	if numRespStated == 0 {
		numRespStated = -1
	}

	smryString := fmt.Sprintf("Stated : %d  Failed : %d.  Flawed Streams: %d.  Mismatched RCs: %d (%3.3f%%).  Avg RTT %f sdev : %f.  Unmatched reqs: %d.  Unmatched resps : %d.  Flawed Reqs : %d.  Flawed Resps : %d.  Dropped : %d Pcap req errs : %d, Pcap resp errs : %d",
		this.stated,
		this.failed,
		numBadStreams,
		this.numMismatchedRCs,
		100*float64(this.numMismatchedRCs)/float64(numRespStated),
		avg,
		std,
		len(streamReqSeqMap),
		len(streamRespSeqMap),
		flawedReqStreams,
		flawedRespStreams,
		this.dropped,
		atomic.LoadUint64(&numPcapReqErrs),
		atomic.LoadUint64(&numPcapRespErrs))

	glog.Infof("Summary : %s\n", smryString)

	if this.logStats {
		this.log.Printf("# Summary:\n")
		this.log.Printf("# %s\n", smryString)
	}

	if (statFile != nil) {
		statFile.Close()
	}

	if (droppedFile != nil) {
		droppedFile.Close()
	}

	glog.Flush()
	this.notifyFinishedChannel <- true
}

func summarize(nums []float64) (avg float64, std float64) {
	length := len(nums)
	if length == 0 {
		return 0,0
	}

	for _, num := range nums {
		avg += num
	}
	avg = avg / float64(length)

	for _, num := range nums {
		diff := avg - num
		std += diff * diff
	}
	std = std / float64(length)

	return
}


