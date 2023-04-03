package parser

import (
	"bufio"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/randolphcyg/cpe"
)

type IProbe interface {
	IsEmpty() bool
}

type IParser interface {
	IsEmpty() bool
}

// Probe nmap service probe
type Probe struct {
	Protocol     string   `json:"protocol"`
	ProbeName    string   `json:"probeName"`
	ProbeString  string   `json:"probeString,omitempty"`
	Ports        []string `json:"ports,omitempty"`
	SslPorts     []string `json:"sslPorts,omitempty"`
	TcpWrappedMs string   `json:"tcpWrappedMs,omitempty"`
	TotalWaitMs  string   `json:"totalWaitMs,omitempty"`
	Rarity       string   `json:"rarity,omitempty"`
	Fallback     string   `json:"fallback,omitempty"`
	Matches      []*Match `json:"matches"`
}

// Match nmap service probe match rule
type Match struct {
	Pattern     string `json:"pattern"`
	Name        string `json:"name"`
	PatternFlag string `json:"patternFlag,omitempty"`
	VersionInfo *VInfo `json:"versionInfo,omitempty"`
}

// VInfo version info, include six optional fields and CPE
type VInfo struct {
	VendorProductName string     `json:"vendorProductName,omitempty"`
	Version           string     `json:"version,omitempty"`
	Info              string     `json:"info,omitempty"`
	Hostname          string     `json:"hostname,omitempty"`
	OperatingSystem   string     `json:"operatingSystem,omitempty"`
	DeviceType        string     `json:"deviceType,omitempty"`
	Cpe               []*cpe.CPE `json:"cpe,omitempty"`
}

func NewProbe() *Probe {
	return &Probe{}
}

func (x *Probe) IsEmpty() bool {
	return reflect.DeepEqual(x, &Probe{})
}

func NewMatch() *Match {
	return &Match{}
}

func NewVInfo() *VInfo {
	return &VInfo{}
}

func (v *VInfo) IsEmpty() bool {
	return reflect.DeepEqual(v, &VInfo{})
}

func handleVInfoField(src, flagStr string) (string, string, error) {
	if len(src) == 0 {
		return "", "", nil
	}

	src = strings.TrimSpace(src)
	isFlagInSrc := strings.Index(src, flagStr)
	if isFlagInSrc == -1 {
		return "", src, nil
	}

	end := strings.IndexByte(src[isFlagInSrc+len(flagStr):], '/')
	if end == -1 {
		return "", src, errors.New("vInfo field end is wrong")
	}

	ret := src[isFlagInSrc+len(flagStr) : isFlagInSrc+len(flagStr)+end]
	srcRet := src[:isFlagInSrc+len(flagStr)] + src[isFlagInSrc+len(flagStr)+end+1:]

	return ret, srcRet, nil
}

func HandleVInfo(src string) (vInfo *VInfo, err error) {
	vInfo = NewVInfo()
	fields := []struct {
		field string
		set   func(string)
	}{
		{"p/", func(v string) { vInfo.VendorProductName = v }},
		{"v/", func(v string) { vInfo.Version = v }},
		{"i/", func(v string) { vInfo.Info = v }},
		{"h/", func(v string) { vInfo.Hostname = v }},
		{"o/", func(v string) { vInfo.OperatingSystem = v }},
		{"d/", func(v string) { vInfo.DeviceType = v }},
	}

	for _, field := range fields {
		fieldValue := ""
		fieldValue, src, err = handleVInfoField(src, field.field)
		if err != nil {
			return
		}

		field.set(fieldValue)
		if len(src) == 0 {
			return
		}
	}

	// CPE handle logic
	cpeSrcStr := ""
	isCpe22FlagInSrc := strings.Index(src, cpe.FlagCpe22)
	if isCpe22FlagInSrc != -1 {
		cpeSrcStr = src[isCpe22FlagInSrc : len(src)-1]
	} else {
		isCpe23FlagInSrc := strings.LastIndex(src, cpe.FlagCpe23)
		if isCpe23FlagInSrc != -1 {
			cpeSrcStr = src[isCpe23FlagInSrc : len(src)-1]
		}
	}

	cpeSlice := strings.SplitN(cpeSrcStr, " ", -1)
	if len(cpeSlice) > 0 {
		for _, c := range cpeSlice {
			cRet, err := cpe.ParseCPE(c)
			if err != nil {
				continue
			}
			vInfo.Cpe = append(vInfo.Cpe, cRet)
		}
	}

	return
}

func ParseMatch(line string) (m *Match, err error) {
	m = NewMatch()
	line = strings.TrimSpace(line)
	line = strings.Replace(line, "\n", "", -1)
	matchSeg := strings.SplitN(line, " ", 3)
	name := matchSeg[1]
	regxSeg := strings.SplitN(matchSeg[2], "|", 3)
	pattern := regxSeg[1]

	patternFlag := ""
	versionInfo := NewVInfo()
	if len(regxSeg) >= 3 {
		versionInfoSeg := strings.SplitN(regxSeg[2], " ", 2)

		if versionInfoSeg[0] != "" {
			patternFlag = versionInfoSeg[0]
		}

		if len(versionInfoSeg) >= 2 {
			tmp, errVInfo := HandleVInfo(versionInfoSeg[1])
			if err != nil {
				m = &Match{
					Pattern:     pattern,
					Name:        name,
					PatternFlag: patternFlag,
					VersionInfo: versionInfo,
				}
				return m, errVInfo
			}
			versionInfo = tmp
		}
	}

	m = &Match{
		Pattern:     pattern,
		Name:        name,
		PatternFlag: patternFlag,
		VersionInfo: versionInfo,
	}

	return
}

func ParseNmapServiceProbe(srcFilePath string) (probes []*Probe, err error) {
	// Open the nmap-service-probes file
	file, err := os.Open(srcFilePath)
	if err != nil {
		return
	}
	defer file.Close()

	probes = make([]*Probe, 0, 200)

	// Create an empty probe to hold current probe being parsed
	currentProbe := NewProbe()

	// Create a scanner to read the file line by line; Loop through each line of the file
	for scanner := bufio.NewScanner(file); scanner.Scan(); {
		line := scanner.Text()

		// Ignore comments and empty lines
		if strings.HasPrefix(line, "#") || len(line) == 0 || strings.HasPrefix(line, "Exclude ") {
			continue
		}

		switch {
		case strings.HasPrefix(line, "#"), len(line) == 0, strings.HasPrefix(line, "Exclude "):
			continue
		case strings.HasPrefix(line, "Probe "): // If the line starts with "Probe", start a new probe
			// If we have an existing probe, append it to the slice of probes
			if currentProbe.ProbeName != "" {
				probes = append(probes, currentProbe)
			}
			// Create a new probe with the name and default values
			currentProbe = NewProbe()

			lineSeg := strings.SplitN(line, " ", 4)
			if lineSeg[1] != "TCP" && lineSeg[1] != "UDP" { // unsupported protocol
				continue
			}
			currentProbe.Protocol = lineSeg[1]
			currentProbe.ProbeName = lineSeg[2]
			probeStringSrc := strings.TrimPrefix(lineSeg[3], "q|")
			probeString := strings.TrimSuffix(probeStringSrc, "|")
			currentProbe.ProbeString = probeString
		case strings.HasPrefix(line, "match "), strings.HasPrefix(line, "softmatch "):
			m, err := ParseMatch(line)
			if err != nil {
				continue
			}
			currentProbe.Matches = append(currentProbe.Matches, m)
		case strings.HasPrefix(line, "ports "):
			currentProbe.Ports = strings.Split(line[len("ports "):], ",")
		case strings.HasPrefix(line, "sslports "):
			currentProbe.SslPorts = strings.Split(line[len("sslports "):], ",")
		case strings.HasPrefix(line, "totalwaitms "):
			currentProbe.TotalWaitMs = line[len("totalwaitms "):]
		case strings.HasPrefix(line, "tcpwrappedms "):
			currentProbe.TcpWrappedMs = line[len("tcpwrappedms "):]
		case strings.HasPrefix(line, "rarity "):
			currentProbe.Rarity = line[len("rarity "):]
		case strings.HasPrefix(line, "fallback "):
			currentProbe.Fallback = line[len("fallback "):]
		}
	}

	// Append the last probe to the slice of probes
	if currentProbe.IsEmpty() {
		return
	}

	probes = append(probes, currentProbe)

	return
}

// UnquoteRawString raw string ==> string
// Replaces the escape characters in the original string with the actual characters
func UnquoteRawString(rawStr string) (string, error) {
	str, err := strconv.Unquote(`"` + rawStr + `"`)
	if err != nil {
		return "", err
	}

	return str, nil
}

// FillVersionInfoFields Replace the versionInfo and CPE placeholder elements with the matched real values
func FillVersionInfoFields(src [][]byte, match *Match) *VInfo {
	versionInfo := match.VersionInfo
	tmpVerInfo := &VInfo{
		VendorProductName: FillHelperFuncOrVariable(versionInfo.VendorProductName, src),
		Version:           FillHelperFuncOrVariable(versionInfo.Version, src),
		Info:              FillHelperFuncOrVariable(versionInfo.Info, src),
		Hostname:          FillHelperFuncOrVariable(versionInfo.Hostname, src),
		OperatingSystem:   FillHelperFuncOrVariable(versionInfo.OperatingSystem, src),
		DeviceType:        FillHelperFuncOrVariable(versionInfo.DeviceType, src),
		Cpe:               nil,
	}

	if len(versionInfo.Cpe) > 0 {
		for _, c := range versionInfo.Cpe {
			tmpCPE := &cpe.CPE{
				Version:   FillHelperFuncOrVariable(c.Version, src),
				Language:  FillHelperFuncOrVariable(c.Language, src),
				Vendor:    FillHelperFuncOrVariable(c.Vendor, src),
				Update:    FillHelperFuncOrVariable(c.Update, src),
				Other:     FillHelperFuncOrVariable(c.Other, src),
				TargetSw:  FillHelperFuncOrVariable(c.TargetSw, src),
				SwEdition: FillHelperFuncOrVariable(c.SwEdition, src),
				TargetHw:  FillHelperFuncOrVariable(c.TargetHw, src),
				Product:   FillHelperFuncOrVariable(c.Product, src),
			}

			tmpVerInfo.Cpe = append(tmpVerInfo.Cpe, tmpCPE)
		}
	}

	return tmpVerInfo
}
