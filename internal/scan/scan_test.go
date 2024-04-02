package scan

import (
	"testing"
)

func TestUnmarshalScan(t *testing.T) {

	scan := UnmarshalScan("../../examples/debian_11.json")

	if len(scan.Matches) != 103 {
		t.Fatalf("ERROR, num of matches is off %d", len(scan.Matches))
	}

	scan = UnmarshalScan("../../examples/grype.json")

	if len(scan.Matches) != 0 {
		t.Fatalf("ERROR, num of matches is off %d", len(scan.Matches))
	}
}
func TestNewLoadScan(t *testing.T) {
	stream := NewJSONStream()
	println("loaded")
	errs := make(chan error, 1)
	go func() {
		for data := range stream.Watch() {
			if data.Error != nil {
				errs <- data.Error
			}
		}
	}()
	stream.LoadScan("../../examples/grype.json")
	err := <-errs
	if err != nil {
		t.Fatal(err)
	}
}

func TestSBOMFindings(t *testing.T) {
	grype := UnmarshalScan("../../examples/debian_11.json")
	sbom := BuildSBOMFindings(&grype)
	if sbom.NumCritical != 2 {
		t.Fatalf("ERROR, num of critical is off %d", sbom.NumCritical)
	}
	if sbom.NumHigh != 12 {
		t.Fatalf("ERROR, num of high is off %d", sbom.NumHigh)
	}
	if sbom.NumInfo != 0 {
		t.Fatalf("ERROR, num of info is off %d", sbom.NumInfo)
	}
	if sbom.NumLow != 7 {
		t.Fatalf("ERROR, num of low is off %d", sbom.NumLow)
	}
	if sbom.NumMedium != 18 {
		t.Fatalf("ERROR, num of medium is off %d", sbom.NumMedium)
	}
}

func TestSBOMFindingsPerID(t *testing.T) {
	grype := UnmarshalScan("../../examples/debian_11.json")
	sbom := BuildSBOMFindingsPerID(&grype)
	for key, val := range *sbom {
		if val.NumCritical != 2 {
			t.Fatalf("ERROR, num of critical is off %v, %s, %d", val, key, val.NumCritical)
		}
		if val.NumHigh != 12 {
			t.Fatalf("ERROR, num of high is off %s, %d", key, val.NumHigh)
		}
		if val.NumInfo != 0 {
			t.Fatalf("ERROR, num of info is off %s, %d", key, val.NumInfo)
		}
		if val.NumLow != 7 {
			t.Fatalf("ERROR, num of low is off %s, %d", key, val.NumLow)
		}
		if val.NumMedium != 18 {
			t.Fatalf("ERROR, num of medium is off %s, %d", key, val.NumMedium)
		}
	}
}
