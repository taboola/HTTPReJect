# HTTPReJect
HTTPReJect is a tool for Re-inJecting (replaying) an HTTP from a packet capture file (pcap) to a benchmark server.
  You can capture pcap files in production and then replay them at an arbitrary clock rate against a test server,
 allowing for easy regression testing with real world data.

HTTPReJect is written in [golang](https://golang.org/) and is heavily influenced by the 
[golang httpassembly example](https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go)

Praise for the fundementals of this replay application really is due to the original go developers that worked on
gopacket, tcpassembly, and the valuable httpassembly examples.  However all bugs, feature deficiencies and ommisions in
HTTPReJect are entirely this author's.
  
  
### features
   * **HTTPReJect** "replays" a pcap file to an http server.  
   * It can replay pcap requests at a fixed rate or at a multiple of their original rate in the pcap file.
   * It can log to disk statistical information on each request sent from the pcap:
      * Round Trip Time
      * Return Code
      * URL
      * Selected get tags
      * Request size
      * Response size
   * **HTTPReJect** can gather statistical information on the original http server response from the pcap and report
      * Original Round Trip Time
      * Original Return Code
      * Original Response size
  
  
## output file format
Replay's output is in CSV format in the following order:

   **Timestamp**
   
    Original timestamp of the request from the pcap file. 
   
   **URL**
   
     Path portion of the URL.
   
   **RC**
   
     HTTP Status Code returned in response to the replayed request.
   
   **RTT**
   
    Round Trip Time in floating point seconds measeured from just before the request is replayed until just after the
    response is received.
   
   **Request Len**
   
     Length of request body.
   
   **Response Len**
   
     Length of the body received in response to the replayed request.
   
   **Time Accuracy**
   
     Difference in floating point seconds from when the request should have been replayed until just before it was
     replayed.  Negative indicates a late request.  As replay will never attempt to send requests earlier than it 
     thinks it should, all accuracy values should be negative. 
   
   **Stream Num**
   
     Replay will number each stream it encounters in the filtered pcap file, starting with 1. 
   
   **Request Num**
   
     The number of sequencial requests encountered per stream starting with 1.
   
   **Original Response Len**
   
     Length of the original response from the pcap file.  If a matched response can not be found in the pcap file, or
     if the option to find responses is not enabled, this value will be 0.
     
   **Original RC**
   
     HTTP Status Code of the original response from the pcap file.  If a matched response can not be found in the pcap
     file, or if the option to find responses is not enabled, this value will be 0.
     
   **Original RTT**
     
     Round Trip Time of the original response from the pcap file.  If a matched response can not be found in the pcap
     file, or if the option to find responses is not enabled, this value will be 0.
     
     Measured as the difference from the packet timestamp of the last packet in the request line and the timestamp of
     the last packet in the response body.
   
   **Walltime Diff**
   
     Clockrate adjusted time from the start of the program just after the end of the response body is read.
   
   **Selected Get Params**
     
     Optional selected get parameters from the pcap request.
     
   **Selected Response Matches**
     
     Optional matches to the respCapture regexp, or the whole response if grabEntireResponse is enabled.

  
     
    
## HTTPReJect usage

  **\-addDTQuery**
  
        Adds pcapreplayts to queries with delta time.  This could be used to for debugging to verify replay is sending
        requests in a timely manner from the http server side.
        
  **\-addToQuery  string**
          
          Add arbitrary string to query.  String should be in the form of parm=val.
        
  **\-alsologtostderr**
  
        log to standard error as well as files.  Set for additional debugging to be output to stderr.  By default much
        of the output is silenced.
  
  **\-assembly_debug_log**
  
        If true, the github.com/google/gopacket/tcpassembly library will log verbose debugging information (at least
        one line per packet)
  
  **\-assembly_memuse_log**
  
        If true, the github.com/google/gopacket/tcpassembly library will log information regarding its memory use every
        once in a while.
  
  **\-dropLaterThan float**
  
        Drop requests later than num seconds.  Defaults to off.  If replay is delayed waiting for concurrent requests
        to be less than maxInflight then it will drop requests later than this value.
  
  **\-dumpPackets**
  
        Dump all packets to stdout for debug.
        
  **\-extraParm value**
 	
        Get Paramater to record in output (default []).
  
  **\-f string**
  
        pcap filter in Berkeley Packet Filter format (default "tcp and dst port 80").
  
  **\-filterRequestURLs string**

       	regex to send only matching requests from pcap.

   **\-forceHostHeader string**
   
       	Force the host header to this value.

  **\-forceRate float**
  
        Force playback rate to num requests/second.
   
   **\-grabEntireResponse**

       	log the entire replay response.

   **\-grabEntireURL**

       	log the entire URL (rather than just the path).

  **\-logDropped string**
  
        path/filename to log dropped request info.  See -dropLaterThan option above.
  
  **\-log_backtrace_at value**
  
        when logging hits line file:N, emit a stack trace (default :0).
  
  **\-log_dir string**
  
        If non-empty, write log files in this directory.
  
  **\-logtostderr**
  
        log to standard error instead of files.  Set for additional debugging to be output to stderr.  By default much
        of the output is silenced.
  
  **\-maxInaccuracy float**
  
        DEBUG: if non-zero, program exits if it falls behind or ahead.
  
  **\-maxInflight uint**
  
        Max inflight at any given time (default 256).  This is the maximum concurrent connections that replay will allow
        to be open to the HTTP server at any point in time.
  
  **\-noSend**
  
        Don't actually send any queries.  For Debug.
  
  **\-p string**
  
        PCAP filename
       
  **\-pcapFlushPeriod float**

     	Flush streams with missing packets after this amount of time (seconds) (default 30).

  **\-pcapReadAheadTime float**
        
        pcap file read ahead time in seconds. (default 0.1)
        This is probably best left unchanged.  It sets the amount of pcap file to read ahead.  Enough pcap file needs
        to be read to allow streams to be reconstructed.  If not enough is read ahead of when its needed requests will
        be sent out late.  If too much is read ahead of when its needed, replay will use more memory and resources to
        buffer sleeping requests.  **\-r float**
  
  **\-r float**

        Playback rate. 2.0 would play a 2 hour pcap in 1 hour (default 1)
  
  **\-rateLimitWarnings string**
  
        Rate Limit Warnings (default "1s").  Some warnings are rate limited so as to not overwhelm output.  Note that
        warnings are off by default also.
  
  **\-readResponse**
  
        expect response in pcap.  If corresponding responses are found, information from them will be added to replay's
        output.  Defaults to true.  Note: unexpected encountered responses are fatal (if readResponse is false).  Adjust
        your pcapFilter accordingly.

  **\-respCapture string**

        regex capture to run against response body

  **\-s string**
  
        server URL (default "http://localhost:80")
  
  **\-stderrthreshold value**
  
        logs at or above this threshold go to stderr.
  
  **\-stopAfterNumReqs uint**
  
        exit after num reqs if non zero.  Defaults to off (0).
  
  **\-t string**
  
        path/filename for statistical output.
  
  **\-v value**
  
        log level for V logs for use in Debug.  1 is informational, 2 is extremely verbose.
  
  **\-vmodule value**
  
        comma-separated list of pattern=N settings for file-filtered logging.

### building
See https://golang.org for more in depth general information on building golang code.

Here's the tl;dr guide to building:

* setup GOPATH:             
    >export GOPATH=$HOME/Go

* get the code & dependencies:
    > go get github.com/taboola/HTTPReJect github.com/golang/glog github.com/google/gopacket
   
* build it:                
    > go build github.com/taboola/HTTPReJect

* that's it!
    > ./HTTPReJect --help

## Windows
Perform these steps, then proceed with the tl;dr version, replacing export with the windows-equivalent of set.
 
 * Download winpcap developer version
    > https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip
 
 * Since winpcap dev is 32-bit only, we must set GOARCH accordingly
    > set GOARCH=386
    
 * Enable CGO
    > set CGO_ENABLED=1
    
 * Ready to go!
