package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	scan "github.com/spitfire21/ctrguard/m/internal/scan"
)

type ScanPolicy struct {
	PolicyName    string
	Enabled       bool
	NonScanLayers int
	NumHigh       int
	NumMedium     int
	NumLow        int
	NumInfo       int
}

func LoadPolicy(path string) ScanPolicy {
	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Println(err)
	}
	var result ScanPolicy
	err = json.Unmarshal(data, &result)
	if err != nil {
		fmt.Println(err)
	}
	return result
}
func VerifyScanPolicy(findings *scan.SBOMFindings, policy *ScanPolicy) bool {
	if findings.NumHigh < policy.NumHigh {
		return false
	}
	if findings.NumMedium < policy.NumMedium {
		return false
	}
	if findings.NumLow < policy.NumLow {
		return false
	}
	if findings.NumInfo < policy.NumInfo {
		return false
	}
	return true

}
