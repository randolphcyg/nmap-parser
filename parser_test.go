package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleVersionInfo(t *testing.T) {
	_, err := handleVInfo("match activesync m|^.\\0\\x01\\0[^\\0]\\0[^\\0]\\0[^\\0]\\0[^\\0]\\0[^\\0]\\0.*\\0\\0\\0$|s p/Microsoft ActiveSync/ o/Windows/ cpe:/a:microsoft:activesync/ cpe:/o:microsoft:windows/a")
	assert.ErrorIs(t, err, nil)
}

func TestParseNmap(t *testing.T) {
	srcFilePath := "nmap-service-probes"
	probes, err := ParseNmap(srcFilePath)
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
	probes, err := ParseNmap(srcFilePath)
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
	asciiApprox := HelperP(utf16Str)
	assert.Equal(t, "WORKGROUP", asciiApprox)
}

func TestHelperSubst(t *testing.T) {
	input := "VanDyke VShell sshd version 2_2_3_578"
	output := HelperSubst(input, "_", ".")
	assert.Equal(t, "VanDyke VShell sshd version 2.2.3.578", output)
}

func TestHelperI(t *testing.T) {
	b := []byte{0x12, 0x34, 0x56, 0x78}
	val1, _ := HelperI('>', b)
	val2, _ := HelperI('<', b)
	assert.Equal(t, 305419896, val1)
	assert.Equal(t, 2018915346, val2)
}
