package scan

import (
	"encoding/json"
	"fmt"
	"os"
)

type Layer struct {
	Id       string `json:"id"`
	Severity string `json:"severity"`
}

type ImageScanInfo struct {
	Name   string  `json:"name"`
	Layers []Layer `json:"layers"`
}

type Metrics struct {
	BaseScore           float64 `json:"baseScore"`
	ImpactScore         float64 `json:"impactScore"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
}

type Cvss struct {
	Source         string      `json:"source"`
	Type_          string      `json:"type"`
	Version        string      `json:"version"`
	Vector         string      `json:"vector"`
	Metrics        Metrics     `json:"metrics"`
	VendorMetadata interface{} `json:"vendorMetadata"`
}
type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}
type Vulnerability struct {
	Id          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	Urls        []string `json:"urls"`
	Description string   `json:"description"`
	Cvss        []string `json:"cvss"`
	Advisories  []string `json:"advisories"`
}
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type MatchDetails struct {
	Type_      string      `json:"type"`
	Matcher    string      `json:"matcher"`
	SearchedBy interface{} `json:"searchedBy"`
	Found      interface{} `json:"found"`
	Namespace  string      `json:"namespace"`
	Package_   Package     `json:"package"`
}

type ArtifactLocation struct {
	Path    string `json:"path"`
	LayerID string `json:"layerId"`
}

type Artifact struct {
	Id       string           `json:"id"`
	Name     string           `json:"name"`
	Version  string           `json:"version"`
	Type_    string           `json:"type"`
	Location ArtifactLocation `json:"location"`
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

type Target struct {
	Type_          string   `json:"type"`
	UserInput      string   `json:"userInput"`
	ImageID        string   `json:"imageId"`
	ManifestDigest string   `json:"manifestDigest"`
	MediaType      string   `json:"mediaType"`
	Tags           []string `json:"tags"`
	ImageSize      int64    `json:"imageSize"`
	Layers         []Layer  `json:"layers"`
	Manifest       string   `json:"manifest"`
	Config         string   `json:"config"`
	RepoDigests    []string `json:"repoDigests"`
	Architecture   string   `json:"architecture"`
	Os             string   `json:"os"`
	Labels         []string `json:"labels"`
}

type Distro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	IdLike  string `json:"idLike"`
}

type Source struct {
	Type_  string `json:"type"`
	Distro Distro `json:"distro"`
}

type GrypeFormat struct {
	Matches []Match `json:"matches"`
	Source
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

// Watch watches JSON streams. Each stream entry will either have an error or a
// User object. Client code does not need to explicitly exit after catching an
// error as the `Start` method will close the channel automatically.
func (s Stream) Watch() <-chan Entry {
	return s.stream
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
