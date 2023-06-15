package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tealeg/xlsx"
)

var client IClient = &Client{}

func TestVInfoIsEmpty(t *testing.T) {
	vInfo := client.NewVInfo()
	assert.Equal(t, true, vInfo.IsEmpty())
}

func TestHandleVersionInfo(t *testing.T) {
	_, err := client.HandleVInfo("match activesync m|^.\\0\\x01\\0[^\\0]\\0[^\\0]\\0[^\\0]\\0[^\\0]\\0[^\\0]\\0.*\\0\\0\\0$|s p/Microsoft ActiveSync/ o/Windows/ cpe:/a:microsoft:activesync/ cpe:/o:microsoft:windows/a")
	assert.ErrorIs(t, err, nil)
}

func TestParseNmapServiceProbe(t *testing.T) {
	srcFilePath := "./tests/nmap-service-probes"
	probes, err := client.ParseNmapServiceProbe(srcFilePath)
	if err != nil {
		panic(err)
	}
	// Convert the probes slice to JSON
	probesJSON, err := json.Marshal(probes)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(string(probesJSON)))
}

func TestParseNmapServiceProbeToJson(t *testing.T) {
	readable := true
	srcFilePath := "./tests/nmap-service-probes"
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
}

func TestHelperP(t *testing.T) {
	utf16Str := "W\000O\000R\000K\000G\000R\000O\000U\000P\000"
	asciiApprox := helperP(utf16Str)
	assert.Equal(t, "WORKGROUP", asciiApprox)
}

func TestHelperSubst(t *testing.T) {
	input := "VanDyke VShell sshd version 2_2_3_578"
	output := helperSubst(input, "_", ".")
	assert.Equal(t, "VanDyke VShell sshd version 2.2.3.578", output)
}

func TestHelperI(t *testing.T) {
	b := []byte{0x12, 0x34, 0x56, 0x78}
	val1 := helperI(">", b)
	val2 := helperI("<", b)
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

	str1 := client.FillHelperFuncOrVariable("i/game: $1; port: $P(2)/", srcData)
	assert.Equal(t, "i/game: gta6; port: 9527/", str1)

	str2 := client.FillHelperFuncOrVariable("i/name: $P(3); description: $P(4)/", srcData)
	assert.Equal(t, "i/name: Mike; description: You forget a thousand things every day/", str2)

	str3 := client.FillHelperFuncOrVariable("cpe:/a:vandyke:vshell:$SUBST(5,\"_\",\".\")/", srcData)
	assert.Equal(t, "cpe:/a:vandyke:vshell:2.2.3.578/", str3)

	str4 := client.FillHelperFuncOrVariable("v/15.00.$I(1,\">\")/", srcData)
	assert.Equal(t, "v/15.00.1735680310/", str4)
}

func TestParseMatch(t *testing.T) {
	// string `i/broken: $1 not found/` has `d/`, the wrong logic maybe set the DeviceType by ` cpe:`
	str := "match amanda m|^ld\\.so\\.1: amandad: fatal: (libsunmath\\.so\\.1): open failed: No such file or directory\\n$| p/Amanda backup system index server/ i/broken: $1 not found/ cpe:/a:amanda:amanda/\n\t"
	match, _ := client.ParseMatch(str)
	assert.Equal(t, "", match.VersionInfo.DeviceType)
}

func TestParseMatchVInfoFieldOutOfOrder(t *testing.T) {
	// the version info fields is out of order
	str := "match amanda m|^ld\\.so\\.1: amandad: fatal: (libsunmath\\.so\\.1): open failed: No such file or directory\\n$| i/broken: $1 not found/ cpe:/a:amanda:amanda/ o/Windows/ p/Amanda backup system index server/\n\t"
	match, _ := client.ParseMatch(str)
	assert.Equal(t, "Windows", match.VersionInfo.OperatingSystem)
}

// TestOutToExcel output probes to excel
func TestOutToExcel(t *testing.T) {
	file := xlsx.NewFile()
	sheet, err := file.AddSheet("nmap-probe-support-service")
	if err != nil {
		panic(err)
	}

	srcFilePath := "./tests/nmap-service-probes"
	probes, err := client.ParseNmapServiceProbe(srcFilePath)
	if err != nil {
		panic(err)
	}

	sheetRowHeader := sheet.AddRow()
	sheetRowHeader.SetHeightCM(2) // 设置行高

	sheetCellHeader1 := sheetRowHeader.AddCell()
	sheetCellHeader1.Value = "服务名"

	sheetCellHeader2 := sheetRowHeader.AddCell()
	sheetCellHeader2.Value = "版本"

	sheetCellHeader3 := sheetRowHeader.AddCell()
	sheetCellHeader3.Value = "运行设备类型"

	sheetCellHeader4 := sheetRowHeader.AddCell()
	sheetCellHeader4.Value = "供应商和服务名称"

	sheetCellHeader5 := sheetRowHeader.AddCell()
	sheetCellHeader5.Value = "更多信息"

	sheetCellHeader6 := sheetRowHeader.AddCell()
	sheetCellHeader6.Value = "服务提供的主机名"

	sheetCellHeader7 := sheetRowHeader.AddCell()
	sheetCellHeader7.Value = "CPE"

	for _, probe := range probes {
		for _, service := range probe.Matches {

			sheetRow := sheet.AddRow()
			sheetRow.SetHeightCM(1) // 设置行高

			sheetCell1 := sheetRow.AddCell()
			sheetCell1.Value = service.Name

			sheetCell2 := sheetRow.AddCell()
			sheetCell2.Value = service.VersionInfo.Version

			sheetCell3 := sheetRow.AddCell()
			sheetCell3.Value = service.VersionInfo.DeviceType

			sheetCell4 := sheetRow.AddCell()
			sheetCell4.Value = service.VersionInfo.VendorProductName

			sheetCell5 := sheetRow.AddCell()
			sheetCell5.Value = service.VersionInfo.Info

			sheetCell6 := sheetRow.AddCell()
			sheetCell6.Value = service.VersionInfo.Hostname

			sheetCell7 := sheetRow.AddCell()
			marshal, _ := json.Marshal(service.VersionInfo.Cpe)

			sheetCell7.Value = string(marshal)

		}
	}

	err = file.Save("./tests/nmap-probe-support-service.xlsx")
	if err != nil {
		panic(err)
	}
}
