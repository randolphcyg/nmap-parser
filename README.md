# nmap-parser

Convert nmap's nmap-service-probes files to go structs and support output as JSON format files

## Usage

```shell
go get "github.com/randolphcyg/nmap-parser"
```

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