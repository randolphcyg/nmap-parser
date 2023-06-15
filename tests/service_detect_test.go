package tests

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	parser "github.com/randolphcyg/nmap-parser"
)

var (
	client        parser.IClient = &parser.Client{}
	ErrConn                      = errors.New("Error connecting")
	ErrSetTimeout                = errors.New("Failed to set deadline")
	ErrSendCmd                   = errors.New("Error sending command")
	ErrRecRsp                    = errors.New("Error receiving response")
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
	// handle custom fingerprint
	if strings.Contains(probe.ProbeString, "{$host}") {
		newProbeString = strings.Replace(probe.ProbeString, "{$host}", host, 1)
	}
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

func TestServiceDetect(t *testing.T) {
	srcFilePath := "nmap-service-probes"
	probes, err := client.ParseNmapServiceProbe(srcFilePath)
	if err != nil {
		panic(err)
	}

	host := "127.0.0.1"
	targetPort := 6379

	serviceName := ""
	info := client.NewVInfo()
	for _, probe := range probes {
		serviceNameTmp, infoTmp, err := ServiceDetect(host, targetPort, probe)
		if err != nil {
			continue
		}

		if serviceNameTmp != "" && !infoTmp.IsEmpty() {
			serviceName = serviceNameTmp
			info = infoTmp
		}

	}

	if serviceName != "" && !info.IsEmpty() {
		assert.Equal(t, "redis", serviceName)
		assert.Equal(t, "Redis key-value store", info.VendorProductName)
	} else {
		assert.Equal(t, "", serviceName)
	}

}
