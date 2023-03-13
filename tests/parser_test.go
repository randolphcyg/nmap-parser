package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/randolphcyg/nmap-parser"
	"github.com/stretchr/testify/assert"
)

func TestHandleVersionInfo(t *testing.T) {
	_, err := parser.HandleVInfo("match activesync m|^.\\0\\x01\\0[^\\0]\\0[^\\0]\\0[^\\0]\\0[^\\0]\\0[^\\0]\\0.*\\0\\0\\0$|s p/Microsoft ActiveSync/ o/Windows/ cpe:/a:microsoft:activesync/ cpe:/o:microsoft:windows/a")
	assert.ErrorIs(t, err, nil)
}

func TestParseNmap(t *testing.T) {
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
	fmt.Println(string(probesJSON))
}

func TestParseNmapAndToJson(t *testing.T) {
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
}

func TestHelperP(t *testing.T) {
	utf16Str := "W\000O\000R\000K\000G\000R\000O\000U\000P\000"
	asciiApprox := parser.HelperP(utf16Str)
	assert.Equal(t, "WORKGROUP", asciiApprox)
}

func TestHelperSubst(t *testing.T) {
	input := "VanDyke VShell sshd version 2_2_3_578"
	output := parser.HelperSubst(input, "_", ".")
	assert.Equal(t, "VanDyke VShell sshd version 2.2.3.578", output)
}

func TestHelperI(t *testing.T) {
	b := []byte{0x12, 0x34, 0x56, 0x78}
	val1 := parser.HelperI(">", b)
	val2 := parser.HelperI("<", b)
	assert.Equal(t, 305419896, val1)
	assert.Equal(t, 2018915346, val2)
}

func TestFillHelperFuncOrVariable(t *testing.T) {
	srcData := [][]byte{
		[]byte("command"),
		[]byte("gta6"),
		[]byte("9527"),
		[]byte("Mike"),
		[]byte("You forget a thousand things every day"),
		[]byte("2_2_3_578"),
	}

	str1, _ := parser.FillHelperFuncOrVariable("i/game: $1; port: $P(2)/", srcData)
	assert.Equal(t, "i/game: gta6; port: 9527/", str1)

	str2, _ := parser.FillHelperFuncOrVariable("i/name: $P(3); description: $P(4)/", srcData)
	assert.Equal(t, "i/name: Mike; description: You forget a thousand things every day/", str2)

	str3, _ := parser.FillHelperFuncOrVariable("cpe:/a:vandyke:vshell:$SUBST(5,\"_\",\".\")/", srcData)
	assert.Equal(t, "cpe:/a:vandyke:vshell:2.2.3.578/", str3)

	str4, _ := parser.FillHelperFuncOrVariable("v/15.00.$I(1,\">\")/", srcData)
	assert.Equal(t, "v/15.00.1735680310/", str4)
}

func TestParseMatch(t *testing.T) {
	// string `i/broken: $1 not found/` has `d/`, the wrong logic maybe set the DeviceType by ` cpe:`
	str := "match amanda m|^ld\\.so\\.1: amandad: fatal: (libsunmath\\.so\\.1): open failed: No such file or directory\\n$| p/Amanda backup system index server/ i/broken: $1 not found/ cpe:/a:amanda:amanda/\n\t"
	match, _ := parser.ParseMatch(str)
	assert.Equal(t, "", match.VersionInfo.DeviceType)
}

func TestParseMatchVInfoFieldOutOfOrder(t *testing.T) {
	// the version info fields is out of order
	str := "match amanda m|^ld\\.so\\.1: amandad: fatal: (libsunmath\\.so\\.1): open failed: No such file or directory\\n$| i/broken: $1 not found/ cpe:/a:amanda:amanda/ o/Windows/ p/Amanda backup system index server/\n\t"
	match, _ := parser.ParseMatch(str)
	assert.Equal(t, "Windows", match.VersionInfo.OperatingSystem)
}
