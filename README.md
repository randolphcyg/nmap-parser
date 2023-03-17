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
	readable := true
	srcFilePath := "nmap-service-probes"
	probes, err := parser.ParseNmap(srcFilePath)
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
	"time"

	"github.com/pkg/errors"
	parser "github.com/randolphcyg/nmap-parser"
)

var (
	ErrConn       = errors.New("Error connecting")
	ErrSetTimeout = errors.New("Failed to set deadline")
	ErrSendCmd    = errors.New("Error sending command")
	ErrRecRsp     = errors.New("Error receiving response")
)

func ServiceDetect(host string, port int, probe parser.Probe) (serviceName string, info parser.VInfo, err error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.Dial(strings.ToLower(probe.Protocol), addr)
	if err != nil {
		err = errors.WithMessage(err, ErrConn.Error())
		return
	}

	// set connect timeout
	timeout := time.Millisecond * 10
	if probe.TcpWrappedMs != "" {
		timeoutCount, _ := strconv.Atoi(probe.TcpWrappedMs)
		timeout = time.Duration(timeoutCount)
	}
	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		err = errors.WithMessage(err, ErrSetTimeout.Error())
		return
	}

	defer conn.Close()

	// send request
	probeStringCMD, _ := parser.UnquoteRawString(probe.ProbeString)
	_, err = conn.Write([]byte(probeStringCMD))
	if err != nil {
		err = errors.WithMessage(err, ErrSendCmd.Error())
		return
	}

	// read respond
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		err = errors.WithMessage(err, ErrRecRsp.Error())
		return
	}

	for _, match := range probe.Matches {
		pattern := match.Pattern
		re, errRgx := regexp.Compile(pattern)
		if errRgx != nil {
			continue
		}
		// Use regular expressions for matching
		srcByte := re.FindSubmatch(resp[:n])

		// find the match rule
		if len(srcByte) > 1 {
			serviceName = match.Name
			info = parser.FillVersionInfoFields(srcByte, match)

			return
		}

	}

	return
}

func main() {
	srcFilePath := "nmap-service-probes"
	probes, err := parser.ParseNmap(srcFilePath)
	if err != nil {
		panic(err)
	}

    host := "127.0.0.1"
	port := 6379

	serviceName := ""
	info := parser.VInfo{}
	for _, probe := range probes {
		serviceNameTmp, infoTmp, err := ServiceDetect(host, port, probe)
		if err != nil {
			continue
		}

		if serviceNameTmp != "" && !infoTmp.IsVInfoEmpty() {
			serviceName = serviceNameTmp
			info = infoTmp
		}

	}

	if serviceName != "" && !info.IsVInfoEmpty() {
		fmt.Println(serviceName, info) 
	} else {
		fmt.Println("no match service!")
	}

}
```