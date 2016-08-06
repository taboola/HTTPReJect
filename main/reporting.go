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

type reporter struct  {
	failed                         int
	stated                         int
	rtts 			       []float64 //history of round trip times

	logStats                       bool
	logDropped                     bool
	expectResponses                bool

	statsLogPath                   string
	droppedLogPath                 string

	doneChannel                    chan bool
	requestReportingChannel        chan *stat
	responseReportingChannel       chan *pcapRespinfo
	droppedRequestReportingChannel chan *reqinfo
	failedRequestsReportingChannel chan bool


	log                            *log.Logger
	droppedLog		       *log.Logger
}

func NewReporter(expectResponses bool, statsLogPath string, droppedLogPath string) *reporter {

	var rep *reporter = new(reporter)
	rep.statsLogPath = statsLogPath
	rep.droppedLogPath = droppedLogPath
	rep.rtts = make([]float64, 0, 10000000)

	rep.logStats = statsLogPath != ""
	rep.logDropped = droppedLogPath != ""

	rep.doneChannel = make(chan bool, 1024)
	rep.requestReportingChannel = make(chan *stat, 1024) // don't block proxys waiting to report stats
	rep.responseReportingChannel = make(chan *pcapRespinfo, 1024)
	rep.droppedRequestReportingChannel = make(chan *reqinfo, 1024)
	rep.failedRequestsReportingChannel = make(chan bool)

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

func (this reporter) Stop() {
	this.doneChannel <- true
}

func (this reporter) SyncFlush() {
	<- this.doneChannel
}

func (this reporter) ReportDropped(droppedRequestInfo *reqinfo) {
	this.droppedRequestReportingChannel <-	droppedRequestInfo
}

func (this reporter) ReportStat(requestStats *stat) {
	this.requestReportingChannel <- requestStats
}

func (this reporter) ReportFailedStat() {
	this.failedRequestsReportingChannel <- true
}

func (this reporter) ReportResponse(responseInfo *pcapRespinfo) {
	this.responseReportingChannel <- responseInfo
}

func (this *stat) String() string {

	extraParms := join(this.getParms, ',')
	respMatches := join(this.respMatch, ',')

	return fmt.Sprintf("%v,%s,%03d,%f,%d,%d,%f,%d,%d,%d,%03d,%f,%f%s%s",
		time.Unix(0, this.TS), this.URL, this.RC, this.RTT, this.ReqLen, this.RespLen, this.TimeAccuracy, this.streamNum,
		this.reqNum, this.OrigRlen, this.OrigRC, this.OrigRTT, this.wallDiff, extraParms, respMatches)
}


func (this reporter) addFailedStat() {
	this.failed++
}

// log the stat if logging is enabled.  Also keep track of failed results
func (this reporter) AddStat(someStat *stat) {
	if someStat != nil {
		this.rtts = append(this.rtts, someStat.RTT)
		this.stated++

		if this.logStats {
			this.log.Println(someStat.String())
		}
	}
}

// goroutine to handle reporting from proxy goroutines
func (this reporter) Report () {

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

	dropped := 0 //amount of dropped requests
	lastStated := 0 //amount of recorded stats for which last calculation of rate was performed
	numMismatchedRCs := 0 //amount of mismatched response codes received by responses during injecting

	lastTime := time.Now() //last measured time by which we perform rate calculation
	finishingUp := false
	for {
		select {
		case someStat := <- this.requestReportingChannel:
			if this.expectResponses && someStat != nil {
				// do we have the other side?
				key := streamKey{someStat.streamNum, someStat.reqNum}
				if presp, is := streamRespSeqMap[key]; is {
					delete(streamRespSeqMap, key)

					presp.OrigRTT = float64(presp.Resptime-someStat.TS) / float64(time.Second)
					someStat.pcapRespinfo = *presp
					this.AddStat(someStat)
					if someStat.OrigRC != someStat.RC {
						numMismatchedRCs++
					}
				} else {
					streamReqSeqMap[key] = someStat
				}
			} else {
				this.AddStat(someStat)
			}

		case someDrop := <- this.droppedRequestReportingChannel:
			dropped++
			if this.logDropped {
				this.droppedLog.Println(someDrop.String())
			}

		case somePcapResp := <- this.responseReportingChannel:
		// do we have the other side?
			if somePcapResp != nil {
				key := streamKey{somePcapResp.respStreamNum, somePcapResp.respNum}
				if reqstat, is := streamReqSeqMap[key]; is {
					delete(streamReqSeqMap, key)
					somePcapResp.OrigRTT = float64(somePcapResp.Resptime-reqstat.TS) / float64(time.Second)
					reqstat.pcapRespinfo = *somePcapResp
					this.AddStat(reqstat)
					if reqstat.OrigRC != reqstat.RC {
						numMismatchedRCs++
					}
				} else {
					streamRespSeqMap[key] = somePcapResp
				}
			}

		case <-this.failedRequestsReportingChannel:
			this.addFailedStat()
		case <-tensecs:
			diffStated := this.stated - lastStated
			lastStated = this.stated

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
				this.stated,
				this.failed,
				atomic.LoadUint64(&numBadStreams),
				atomic.LoadUint64(&totNumReqs),
				atomic.LoadUint64(&numProxySent),
				atomic.LoadUint64(&numProxySleeping),
				atomic.LoadUint64(&numProxyInFlight),
				atomic.LoadUint64(&numLateDropped))

		case <-this.doneChannel:
		// This is a little ugly, but we need to still process anything left in the statRepChan, but we can't
		// pend on the chan:
			finishingUp = true

		default:
			if finishingUp {
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
				var avg float64 = 0
				var std float64 = 0
				for _, rtt := range this.rtts {
					avg += rtt
				}
				if nv := len(this.rtts); nv != 0 {
					avg = avg / float64(nv)
				}

				for _, rtt := range this.rtts {
					diff := avg - rtt
					std += diff * diff
				}
				if nv := len(this.rtts); nv != 0 {
					std = std / float64(nv)
				}

				numRespStated := this.stated - len(streamReqSeqMap)
				// prevent DVZ
				if numRespStated == 0 {
					numRespStated = -1
				}

				smryString := fmt.Sprintf("Stated : %d  Failed : %d.  Flawed Streams: %d.  Mismatched RCs: %d (%3.3f%%).  Avg RTT %f sdev : %f.  Unmatched reqs: %d.  Unmatched resps : %d.  Flawed Reqs : %d.  Flawed Resps : %d.  Dropped : %d Pcap req errs : %d, Pcap resp errs : %d",
					this.stated,
					this.failed,
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

				if this.logStats {
					this.log.Printf("# Summary:\n")
					this.log.Printf("# %s\n", smryString)
				}

				statfile.Close()

				this.doneChannel <- true
				return
			}
		}
	}
}


