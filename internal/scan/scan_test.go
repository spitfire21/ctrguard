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
