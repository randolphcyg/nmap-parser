package parser

import (
	"bufio"
	"fmt"
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
	Operatingsystem   string    `json:"operatingsystem"`
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
	Probename    string   `json:"probename"`
	Probestring  string   `json:"probestring"`
	Ports        []string `json:"ports"`
	Sslports     []string `json:"sslports"`
	Tcpwrappedms string   `json:"tcpwrappedms"`
	Totalwaitms  string   `json:"totalwaitms"`
	Rarity       string   `json:"rarity"`
	Fallback     string   `json:"fallback"`
	Matches      []Match  `json:"matches"`
}

func (x Probe) IsProbeEmpty() bool {
	return reflect.DeepEqual(x, Probe{})
}

var vInfoSplitFlag = []string{"p/", "v/", "i/", "h/", "o/", "d/"}

func handleVInfo(src string) (vInfo VInfo, err error) {
	for _, splitFlag := range vInfoSplitFlag {
		isFlagInSrc := strings.Index(src, splitFlag)

		if isFlagInSrc != -1 {
			ret := ""
			end := strings.Index(src[isFlagInSrc+len(splitFlag):], "/")
			if end == -1 {
				continue
			}
			ret = src[isFlagInSrc+len(splitFlag) : isFlagInSrc+len(splitFlag)+end]

			switch splitFlag {
			case "p/":
				vInfo.VendorProductName = ret
			case "v/":
				vInfo.Version = ret
			case "i/":
				vInfo.Info = ret
			case "h/":
				vInfo.Hostname = ret
			case "o/":
				vInfo.Operatingsystem = ret
			case "d/":
				vInfo.DeviceType = ret
			default:
			}

		}

	}

	var cpesStr string
	cpe22Flag := "cpe:/"
	isCpe22FlagInSrc := strings.Index(src, cpe22Flag)
	if isCpe22FlagInSrc != -1 {
		cpesStr = src[isCpe22FlagInSrc : len(src)-1]
	}

	cpe23Flag := "cpe:2.3"
	isCpe23FlagInSrc := strings.LastIndex(src, cpe23Flag)
	if isCpe23FlagInSrc != -1 {
		cpesStr = src[isCpe23FlagInSrc : len(src)-1]
	}

	cpes := strings.Split(cpesStr, " ")
	for _, c := range cpes {
		cRet, err := cpe.ParseCPE(c)
		if err != nil {
			continue
		}
		vInfo.Cpe = append(vInfo.Cpe, *cRet)
	}

	return
}

func ParseNmap(srcFilePath string) (probes []Probe) {
	// Open the nmap-service-probes file
	file, err := os.Open(srcFilePath)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
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
			if currentProbe.Probename != "" {
				probes = append(probes, currentProbe)
			}

			// Create a new probe with the name and default values
			currentProbe = Probe{
				Probename:    "",
				Protocol:     "",
				Probestring:  "",
				Ports:        nil,
				Sslports:     nil,
				Tcpwrappedms: "",
				Totalwaitms:  "",
				Rarity:       "",
				Fallback:     "",
				Matches:      nil,
			}

			lineSeg := strings.SplitN(line, " ", 4)
			if lineSeg[1] != "TCP" && lineSeg[1] != "UDP" {
				fmt.Println("不支持的协议")
				continue
			}
			currentProbe.Protocol = lineSeg[1]
			currentProbe.Probename = lineSeg[2]

			probestringSrc := strings.TrimLeft(lineSeg[3], "q|")
			probestring := strings.TrimRight(probestringSrc, "|")
			currentProbe.Probestring = probestring

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
			currentProbe.Sslports = strings.Split(line[len("sslports "):], ",")
		} else if strings.HasPrefix(line, "totalwaitms ") {
			currentProbe.Totalwaitms = line[len("totalwaitms "):]
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			currentProbe.Tcpwrappedms = line[len("tcpwrappedms "):]
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
