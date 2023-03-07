package parser

import (
	"bufio"
	"github.com/pkg/errors"
	"os"
	"reflect"
	"strings"

	"github.com/randolphcyg/cpe"
)

// VInfo version info, include six optional fields and CPE
type VInfo struct {
	VendorProductName string    `json:"vendorproductname"`
	Version           string    `json:"version"`
	Info              string    `json:"info"`
	Hostname          string    `json:"hostname"`
	OperatingSystem   string    `json:"operatingsystem"`
	DeviceType        string    `json:"devicetype"`
	Cpe               []cpe.CPE `json:"cpe"`
}

type Match struct {
	Pattern     string `json:"pattern"`
	Name        string `json:"name"`
	PatternFlag string `json:"pattern_flag"`
	VersionInfo VInfo  `json:"versioninfo"`
}

type Probe struct {
	Protocol     string   `json:"protocol"`
	ProbeName    string   `json:"probename"`
	ProbeString  string   `json:"probestring"`
	Ports        []string `json:"ports"`
	SslPorts     []string `json:"sslports"`
	TcpWrappedMs string   `json:"tcpwrappedms"`
	TotalWaitMs  string   `json:"totalwaitms"`
	Rarity       string   `json:"rarity"`
	Fallback     string   `json:"fallback"`
	Matches      []Match  `json:"matches"`
}

func (x Probe) IsProbeEmpty() bool {
	return reflect.DeepEqual(x, Probe{})
}

func handleVInfoField(src, flagStr string) (ret string, err error) {
	isFlagInSrc := strings.Index(src, flagStr)
	if isFlagInSrc != -1 {
		end := strings.Index(src[isFlagInSrc+len(flagStr):], "/")
		if end == -1 {
			return "", errors.New("vInfo field end is wrong")
		}
		ret = src[isFlagInSrc+len(flagStr) : isFlagInSrc+len(flagStr)+end]
	}

	return
}

func handleVInfo(src string) (vInfo VInfo, err error) {
	fieldP, err := handleVInfoField(src, "p/")
	if err != nil {
		return
	}
	vInfo.VendorProductName = fieldP

	fieldV, err := handleVInfoField(src, "v/")
	if err != nil {
		return
	}
	vInfo.Version = fieldV

	fieldI, err := handleVInfoField(src, "i/")
	if err != nil {
		return
	}
	vInfo.Info = fieldI

	fieldH, err := handleVInfoField(src, "h/")
	if err != nil {
		return
	}
	vInfo.Hostname = fieldH

	fieldO, err := handleVInfoField(src, "o/")
	if err != nil {
		return
	}
	vInfo.OperatingSystem = fieldO

	fieldD, err := handleVInfoField(src, "d/")
	if err != nil {
		return
	}
	vInfo.DeviceType = fieldD

	// CPE handle logic
	cpeSrcStr := ""
	cpeFlag := "cpe:/"
	isCpe22FlagInSrc := strings.Index(src, cpeFlag)
	if isCpe22FlagInSrc != -1 {
		cpeSrcStr = src[isCpe22FlagInSrc : len(src)-1]
	} else {
		cpeFlag = "cpe:2.3"
		isCpe23FlagInSrc := strings.LastIndex(src, cpeFlag)
		if isCpe23FlagInSrc != -1 {
			cpeSrcStr = src[isCpe23FlagInSrc : len(src)-1]
		}
	}

	cpeSlice := strings.Split(cpeSrcStr, " ")
	if len(cpeSlice) > 0 {
		for _, c := range cpeSlice {
			cRet, err := cpe.ParseCPE(c)
			if err != nil {
				continue
			}
			vInfo.Cpe = append(vInfo.Cpe, *cRet)
		}
	}

	return
}

func ParseNmap(srcFilePath string) (probes []Probe, err error) {
	// Open the nmap-service-probes file
	file, err := os.Open(srcFilePath)
	if err != nil {
		return
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	// Create an empty probe to hold current probe being parsed
	var currentProbe Probe

	// Loop through each line of the file
	for scanner.Scan() {
		line := scanner.Text()

		// Ignore comments and empty lines
		if strings.HasPrefix(line, "#") || len(line) == 0 || strings.HasPrefix(line, "Exclude ") {
			continue
		}

		// If the line starts with "Probe", start a new probe
		if strings.HasPrefix(line, "Probe ") {
			// If we have an existing probe, append it to the slice of probes
			if currentProbe.ProbeName != "" {
				probes = append(probes, currentProbe)
			}

			// Create a new probe with the name and default values
			currentProbe = Probe{
				ProbeName:    "",
				Protocol:     "",
				ProbeString:  "",
				Ports:        nil,
				SslPorts:     nil,
				TcpWrappedMs: "",
				TotalWaitMs:  "",
				Rarity:       "",
				Fallback:     "",
				Matches:      nil,
			}

			lineSeg := strings.SplitN(line, " ", 4)
			if lineSeg[1] != "TCP" && lineSeg[1] != "UDP" { // unsupported protocol
				continue
			}
			currentProbe.Protocol = lineSeg[1]
			currentProbe.ProbeName = lineSeg[2]

			probeStringSrc := strings.TrimLeft(lineSeg[3], "q|")
			probeString := strings.TrimRight(probeStringSrc, "|")
			currentProbe.ProbeString = probeString

		} else if strings.HasPrefix(line, "match ") || strings.HasPrefix(line, "softmatch ") {
			matchSeg := strings.SplitN(line, " ", 3)
			name := matchSeg[1]
			regxSeg := strings.SplitN(matchSeg[2], "|", 3)
			pattern := regxSeg[1]

			patternFlag := ""
			var versionInfo VInfo
			if len(regxSeg) >= 3 {
				versionInfoSeg := strings.SplitN(regxSeg[2], " ", 2)

				if versionInfoSeg[0] != "" {
					patternFlag = versionInfoSeg[0]
				}

				if len(versionInfoSeg) >= 2 {
					tmp, err := handleVInfo(versionInfoSeg[1])
					if err != nil {
						continue
					}
					versionInfo = tmp
				}
			}

			currentProbe.Matches = append(currentProbe.Matches, Match{
				Pattern:     pattern,
				Name:        name,
				PatternFlag: patternFlag,
				VersionInfo: versionInfo,
			})

		} else if strings.HasPrefix(line, "ports ") {
			currentProbe.Ports = strings.Split(line[len("ports "):], ",")
		} else if strings.HasPrefix(line, "sslports ") {
			currentProbe.SslPorts = strings.Split(line[len("sslports "):], ",")
		} else if strings.HasPrefix(line, "totalwaitms ") {
			currentProbe.TotalWaitMs = line[len("totalwaitms "):]
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			currentProbe.TcpWrappedMs = line[len("tcpwrappedms "):]
		} else if strings.HasPrefix(line, "rarity ") {
			currentProbe.Rarity = line[len("rarity "):]
		} else if strings.HasPrefix(line, "fallback ") {
			currentProbe.Fallback = line[len("fallback "):]
		}

	}

	// Append the last probe to the slice of probes
	if currentProbe.IsProbeEmpty() {
		return
	}

	probes = append(probes, currentProbe)

	return
}
