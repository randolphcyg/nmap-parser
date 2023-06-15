# nmap-parser

Convert nmap's nmap-service-probe file into a go structure for service probing.
Directly use the probe file for service identification, and make the rate higher than the nmap tool itself through custom logic.

## Usage

```shell
go get "github.com/randolphcyg/nmap-parser"
```

you can download the latest nmap probe file: [nmap-service-probes](https://github.com/nmap/nmap/blob/master/nmap-service-probes)

### 1. Convert the NMAP probe file to JSON format and save it as a JSON file

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	parser "github.com/randolphcyg/nmap-parser"
)

func main() {
	client := &parser.Client{}
	readable := true
	srcFilePath := "nmap-service-probes"
	probes, err := client.ParseNmapServiceProbe(srcFilePath)
	if err != nil {
		panic(err)
	}

	// Convert the probes slice to JSON
	probesJSON, err := json.Marshal(probes)
	if err != nil {
		panic(err)
	}

	// Save the probes JSON to a file
	err = os.WriteFile(srcFilePath+".json", probesJSON, 0644)
	if err != nil {
		panic(err)
	}

	if readable {
		// Convert the probes slice to JSON
		probesJSON, err := json.MarshalIndent(probes, "", "    ")
		if err != nil {
			panic(err)
		}

		// Save the probes JSON to a file
		err = os.WriteFile(srcFilePath+"_Readable.json", probesJSON, 0644)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Done")
}
```

### 2. Perform service probe on local port 3306



```go
package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	parser "github.com/randolphcyg/nmap-parser"
)

var (
	client        parser.IClient = &parser.Client{}
	ErrConn       = errors.New("Error connecting")
	ErrSetTimeout = errors.New("Failed to set deadline")
	ErrSendCmd    = errors.New("Error sending command")
	ErrRecRsp     = errors.New("Error receiving response")
)

type MatchResult struct {
	ServiceName string
	Info        *parser.VInfo
}

// matchPattern match the rules of probe
func matchPattern(match *parser.Match, resp []byte, wg *sync.WaitGroup, resultChan chan MatchResult) {
	defer wg.Done()

	pattern := match.Pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		return
	}

	// Use regular expressions for matching
	srcByte := re.FindSubmatch(resp)

	// find the match rule
	if len(srcByte) > 0 {
		info := client.FillVersionInfoFields(srcByte, match)
		result := MatchResult{
			ServiceName: match.Name,
			Info:        info,
		}
		resultChan <- result
	}
}

func ServiceDetect(host string, port int, probe *parser.Probe) (serviceName string, info *parser.VInfo, err error) {
	// set up connection
	conn, err := net.DialTimeout(strings.ToLower(probe.Protocol), net.JoinHostPort(host, strconv.Itoa(port)), time.Millisecond*20)
	if err != nil {
		err = errors.WithMessage(err, ErrConn.Error())
		return
	}
	defer conn.Close()

	// send raw request
	newProbeString := probe.ProbeString
	payload, _ := client.UnquoteRawString(newProbeString)
	_, err = conn.Write([]byte(payload))
	if err != nil {
		err = errors.WithMessage(err, ErrSendCmd.Error())
		return
	}

	// set read timeout
	readTimeout := time.Millisecond * 20
	if probe.TcpWrappedMs != "" {
		timeoutCount, _ := strconv.Atoi(probe.TcpWrappedMs)
		readTimeout = time.Duration(timeoutCount)
	}
	err = conn.SetReadDeadline(time.Now().Add(readTimeout))
	if err != nil {
		err = errors.WithMessage(err, ErrSetTimeout.Error())
		return
	}

	// read respond
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		err = errors.WithMessage(err, ErrRecRsp.Error())
		return
	}

	concurrencyLimit := 20                                   // concurrency of match
	wg := sync.WaitGroup{}                                   // wait for all match task end
	resultChan := make(chan MatchResult, len(probe.Matches)) // channel for receive result

	// signal for match concurrency
	signal := make(chan struct{}, concurrencyLimit)

	// concurrency matching tasks
	for _, match := range probe.Matches {
		wg.Add(1)
		go func(match *parser.Match) {
			signal <- struct{}{} // get signal
			matchPattern(match, resp[:n], &wg, resultChan)
			<-signal // release signal
		}(match)
	}

	// wait for all match task end
	wg.Wait()

	// close channel
	close(resultChan)

	// handle match results
	for result := range resultChan {
		serviceName = result.ServiceName
		info = result.Info
	}

	return
}

func main() {
	srcFilePath := "nmap-service-probes"
	probes, err := client.ParseNmapServiceProbe(srcFilePath)
	if err != nil {
		panic(err)
	}

	host := "127.0.0.1"
	port := 6379

	serviceName := ""
	info := client.NewVInfo()
	for _, probe := range probes {
		serviceNameTmp, infoTmp, err := ServiceDetect(host, port, probe)
		if err != nil {
			continue
		}

		if serviceNameTmp != "" && !infoTmp.IsEmpty() {
			serviceName = serviceNameTmp
			info = infoTmp
		}

	}

	if serviceName != "" && !info.IsEmpty() {
		fmt.Println(serviceName, info)
	} else {
		fmt.Println("no match service!")
	}

}
```