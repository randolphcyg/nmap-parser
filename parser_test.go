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
