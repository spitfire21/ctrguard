package scan

import (
	"encoding/json"
	"fmt"
	"os"
)

type Layer struct {
	id       string `json:"id"`
	severity string `json:"severity"`
}

type ImageScanInfo struct {
	Name   string  `json:"name"`
	Layers []Layer `json:"layers"`
}

type Metrics struct {
	baseScore           float64 `json:"baseScore"`
	impactScore         float64 `json:"impactScore"`
	exploitabilityScore float64 `json:"exploitabilityScore"`
}

type Cvss struct {
	source         string      `json:"source"`
	type_          string      `json:"type"`
	version        string      `json:"version"`
	vector         string      `json:"vector"`
	metrics        Metrics     `json:"metrics"`
	vendorMetadata interface{} `json:"vendorMetadata"`
}
type Fix struct {
	versions []string `json:"versions"`
	state    string   `json:"state"`
}
type Vulnerability struct {
	id          string   `json:"id"`
	dataSource  string   `json:"dataSource"`
	namespace   string   `json:"namespace"`
	severity    string   `json:"severity"`
	urls        []string `json:"urls"`
	description string   `json:"description"`
	cvss        []string `json:"cvss"`
	advisories  []string `json:"advisories"`
}
type Package struct {
	name    string `json:"name"`
	version string `json:"version"`
}
type MatchDetails struct {
	type_      string      `json:"type"`
	matcher    string      `json:"matcher"`
	searchedBy interface{} `json:"searchedBy"`
	found      interface{} `json:"found"`
	namespace  string      `json:"namespace"`
	package_   Package     `json:"package"`
}

type ArtifactLocation struct {
	path    string `json:"path"`
	layerID string `json:"layerId"`
}

type Artifact struct {
	id       string           `json:"id"`
	name     string           `json:"name"`
	version  string           `json:"version"`
	type_    string           `json:"type"`
	location ArtifactLocation `json:"location"`
}

type Match struct {
	Vulnerability          Vulnerability   `json:"vulnerability"`
	RelatedVulnerabilities []Vulnerability `json:"relatedVulnerabilities"`
	Description            string          `json:"description"`
	Cvss                   Cvss            `json:"cvss"`
	Fix                    Fix             `json:"fix"`
	MatchDetails           MatchDetails    `json:"matchDetails"`
	Artifact               Artifact        `json:"artifact"`
}

type ScanInfo struct {
	Matches []ImageScanInfo `json:"matches"`
}
type Entry struct {
	Match Match
	Error error
}

type Stream struct {
	stream chan Entry
}

func NewJSONStream() Stream {
	return Stream{
		stream: make(chan Entry),
	}
}

func (s Stream) LoadScan(path string) {
	defer close(s.stream)

	// Open file to read.
	file, err := os.Open(path)
	if err != nil {
		s.stream <- Entry{Error: fmt.Errorf("open file: %w", err)}
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)

	// Read opening delimiter. `[` or `{`
	if _, err := decoder.Token(); err != nil {
		s.stream <- Entry{Error: fmt.Errorf("decode opening delimiter: %w", err)}
		return
	}

	// Read file content as long as there is something.
	i := 1
	for decoder.More() {
		var match Match
		if err := decoder.Decode(&match); err != nil {
			s.stream <- Entry{Error: fmt.Errorf("decode line %d: %w", i, err)}
			return
		}
		s.stream <- Entry{Match: match}

		i++
	}

	// Read closing delimiter. `]` or `}`
	if _, err := decoder.Token(); err != nil {
		s.stream <- Entry{Error: fmt.Errorf("decode closing delimiter: %w", err)}
		return
	}
}
