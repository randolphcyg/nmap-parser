package tests

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

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

func TestServiceDetect(t *testing.T) {
	srcFilePath := "nmap-service-probes"
	probes, err := parser.ParseNmap(srcFilePath)
	if err != nil {
		panic(err)
	}

	host := "127.0.0.1"
	targetPort := 6379

	serviceName := ""
	info := parser.VInfo{}
	for _, probe := range probes {
		serviceNameTmp, infoTmp, err := ServiceDetect(host, targetPort, probe)
		if err != nil {
			continue
		}

		if serviceNameTmp != "" && !infoTmp.IsVInfoEmpty() {
			serviceName = serviceNameTmp
			info = infoTmp
		}

	}

	if serviceName != "" && !info.IsVInfoEmpty() {
		assert.Equal(t, "redis", serviceName)
		assert.Equal(t, "Redis key-value store", info.VendorProductName)
	} else {
		assert.Equal(t, "", serviceName)
	}

}
