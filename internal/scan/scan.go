package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

type GrypeFormat struct {
	Matches    []Matches  `json:"matches"`
	Source     Source     `json:"source"`
	Distro     Distro     `json:"distro"`
	Descriptor Descriptor `json:"descriptor"`
}
type Fix struct {
	Versions []any  `json:"versions"`
	State    string `json:"state"`
}
type Vulnerability struct {
	ID          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	Urls        []string `json:"urls"`
	Description string   `json:"description"`
	Cvss        []any    `json:"cvss"`
	Fix         Fix      `json:"fix"`
	Advisories  []any    `json:"advisories"`
}
type Metrics struct {
	BaseScore           float64 `json:"baseScore"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}
type VendorMetadata struct {
}
type Cvss struct {
	Source         string         `json:"source"`
	Type           string         `json:"type"`
	Version        string         `json:"version"`
	Vector         string         `json:"vector"`
	Metrics        Metrics        `json:"metrics"`
	VendorMetadata VendorMetadata `json:"vendorMetadata"`
}
type RelatedVulnerabilities struct {
	ID          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Namespace   string   `json:"namespace"`
	Severity    string   `json:"severity"`
	Urls        []string `json:"urls"`
	Description string   `json:"description"`
	Cvss        []Cvss   `json:"cvss"`
}
type Distro0 struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type SearchedBy struct {
	Distro    Distro  `json:"distro"`
	Namespace string  `json:"namespace"`
	Package   Package `json:"package"`
}
type Found struct {
	VersionConstraint string `json:"versionConstraint"`
	VulnerabilityID   string `json:"vulnerabilityID"`
}
type MatchDetails struct {
	Type       string     `json:"type"`
	Matcher    string     `json:"matcher"`
	SearchedBy SearchedBy `json:"searchedBy"`
	Found      Found      `json:"found"`
}
type Locations struct {
	Path    string `json:"path"`
	LayerID string `json:"layerID"`
}
type Artifact struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Version   string      `json:"version"`
	Type      string      `json:"type"`
	Locations []Locations `json:"locations"`
	Language  string      `json:"language"`
	Licenses  []string    `json:"licenses"`
	Cpes      []string    `json:"cpes"`
	Purl      string      `json:"purl"`
	Upstreams []any       `json:"upstreams"`
}
type Vulnerability0 struct {
	ID         string   `json:"id"`
	DataSource string   `json:"dataSource"`
	Namespace  string   `json:"namespace"`
	Severity   string   `json:"severity"`
	Urls       []string `json:"urls"`
	Cvss       []any    `json:"cvss"`
	Fix        Fix      `json:"fix"`
	Advisories []any    `json:"advisories"`
}
type Matches struct {
	Vulnerability          Vulnerability            `json:"vulnerability,omitempty"`
	RelatedVulnerabilities []RelatedVulnerabilities `json:"relatedVulnerabilities"`
	MatchDetails           []MatchDetails           `json:"matchDetails"`
	Artifact               Artifact                 `json:"artifact"`
	//Vulnerability0         Vulnerability0           `json:"vulnerability,omitempty"`
}
type Layers struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}
type Target struct {
	UserInput      string   `json:"userInput"`
	ImageID        string   `json:"imageID"`
	ManifestDigest string   `json:"manifestDigest"`
	MediaType      string   `json:"mediaType"`
	Tags           []string `json:"tags"`
	ImageSize      int      `json:"imageSize"`
	Layers         []Layers `json:"layers"`
	Manifest       string   `json:"manifest"`
	Config         string   `json:"config"`
	RepoDigests    []string `json:"repoDigests"`
	Architecture   string   `json:"architecture"`
	Os             string   `json:"os"`
}
type Source struct {
	Type   string `json:"type"`
	Target Target `json:"target"`
}
type Distro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	IDLike  []any  `json:"idLike"`
}
type Search struct {
	Scope             string `json:"scope"`
	UnindexedArchives bool   `json:"unindexed-archives"`
	IndexedArchives   bool   `json:"indexed-archives"`
}
type Db0 struct {
	CacheDir              string `json:"cache-dir"`
	UpdateURL             string `json:"update-url"`
	CaCert                string `json:"ca-cert"`
	AutoUpdate            bool   `json:"auto-update"`
	ValidateByHashOnStart bool   `json:"validate-by-hash-on-start"`
	ValidateAge           bool   `json:"validate-age"`
	MaxAllowedBuiltAge    int64  `json:"max-allowed-built-age"`
}
type Maven struct {
	SearchUpstreamBySha1 bool   `json:"searchUpstreamBySha1"`
	BaseURL              string `json:"baseUrl"`
}
type ExternalSources struct {
	Enable bool  `json:"enable"`
	Maven  Maven `json:"maven"`
}
type Java struct {
	UsingCpes bool `json:"using-cpes"`
}
type Dotnet struct {
	UsingCpes bool `json:"using-cpes"`
}
type Golang struct {
	UsingCpes             bool `json:"using-cpes"`
	AlwaysUseCpeForStdlib bool `json:"always-use-cpe-for-stdlib"`
}
type Javascript struct {
	UsingCpes bool `json:"using-cpes"`
}
type Python struct {
	UsingCpes bool `json:"using-cpes"`
}
type Ruby struct {
	UsingCpes bool `json:"using-cpes"`
}
type Rust struct {
	UsingCpes bool `json:"using-cpes"`
}
type Stock struct {
	UsingCpes bool `json:"using-cpes"`
}
type Match struct {
	Java       Java       `json:"java"`
	Dotnet     Dotnet     `json:"dotnet"`
	Golang     Golang     `json:"golang"`
	Javascript Javascript `json:"javascript"`
	Python     Python     `json:"python"`
	Ruby       Ruby       `json:"ruby"`
	Rust       Rust       `json:"rust"`
	Stock      Stock      `json:"stock"`
}
type Registry struct {
	InsecureSkipTLSVerify bool   `json:"insecure-skip-tls-verify"`
	InsecureUseHTTP       bool   `json:"insecure-use-http"`
	Auth                  any    `json:"auth"`
	CaCert                string `json:"ca-cert"`
}
type Configuration struct {
	Output                 []string        `json:"output"`
	File                   string          `json:"file"`
	Distro                 string          `json:"distro"`
	AddCpesIfNone          bool            `json:"add-cpes-if-none"`
	OutputTemplateFile     string          `json:"output-template-file"`
	CheckForAppUpdate      bool            `json:"check-for-app-update"`
	OnlyFixed              bool            `json:"only-fixed"`
	OnlyNotfixed           bool            `json:"only-notfixed"`
	IgnoreWontfix          string          `json:"ignore-wontfix"`
	Platform               string          `json:"platform"`
	Search                 Search          `json:"search"`
	Ignore                 any             `json:"ignore"`
	Exclude                []any           `json:"exclude"`
	Db                     Db              `json:"db"`
	ExternalSources        ExternalSources `json:"externalSources"`
	Match                  Match           `json:"match"`
	FailOnSeverity         string          `json:"fail-on-severity"`
	Registry               Registry        `json:"registry"`
	ShowSuppressed         bool            `json:"show-suppressed"`
	ByCve                  bool            `json:"by-cve"`
	Name                   string          `json:"name"`
	DefaultImagePullSource string          `json:"default-image-pull-source"`
	VexDocuments           []any           `json:"vex-documents"`
	VexAdd                 []any           `json:"vex-add"`
}
type Db struct {
	Built         time.Time `json:"built"`
	SchemaVersion int       `json:"schemaVersion"`
	Location      string    `json:"location"`
	Checksum      string    `json:"checksum"`
	Error         any       `json:"error"`
}
type Descriptor struct {
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	Configuration Configuration `json:"configuration"`
	Db            Db            `json:"db"`
	Timestamp     string        `json:"timestamp"`
}

type Entry struct {
	Grype GrypeFormat
	Error error
}

type Stream struct {
	stream chan Entry
}

func UnmarshalScan(path string) GrypeFormat {
	file, err := os.Open(path)

	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	var result GrypeFormat
	err = json.Unmarshal(data, &result)
	if err != nil {
		log.Fatal(err)
	}
	return result
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

// LoadScan loads a JSON stream
// TODO currently broken, need to investigate why
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
		var grype GrypeFormat
		if err := decoder.Decode(&grype); err != nil {
			s.stream <- Entry{Error: fmt.Errorf("decode line %d: %w", i, err)}
			return
		}
		s.stream <- Entry{Grype: grype}

		i++
	}

	// Read closing delimiter. `]` or `}`
	if _, err := decoder.Token(); err != nil {
		s.stream <- Entry{Error: fmt.Errorf("decode closing delimiter: %w", err)}
		return
	}
}

var layerVulnerabilties = map[string]SBOMFindings{}

func setLayerVulnerabilities(findings *SBOMFindings, layer string) {
	layerVulnerabilties[layer] = *findings
}

func GetNumberOfSeverities(grype *GrypeFormat) map[string]int {
	severities := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}

	for _, entry := range grype.Matches {
		severities[strings.ToUpper(entry.Vulnerability.Severity)]++
	}

	return severities
}

func BuildSBOMFindings(grype *GrypeFormat) *SBOMFindings {
	findings := &SBOMFindings{}

	for _, entry := range grype.Matches {
		switch strings.ToUpper(entry.Vulnerability.Severity) {
		case "CRITICAL":
			findings.NumCritical++
		case "HIGH":
			findings.NumHigh++
		case "MEDIUM":
			findings.NumMedium++
		case "LOW":
			findings.NumLow++
		case "INFO":
			findings.NumInfo++
		}
	}
	return findings
}
func BuildSBOMFindingsPerID(grype *GrypeFormat) *map[string]SBOMFindings {

	findings := map[string]SBOMFindings{}

	for _, entry := range grype.Matches {
		for _, artifact := range entry.Artifact.Locations {
			if _, ok := findings[artifact.LayerID]; !ok {
				findings[artifact.LayerID] = SBOMFindings{
					NumCritical: 0,
					NumHigh:     0,
					NumMedium:   0,
					NumLow:      0,
					NumInfo:     0,

					Vulnerabilities: map[string]VulnerabilitySBOM{},
				}
			}
			if val, ok := findings[artifact.LayerID]; ok {
				if _, ok := findings[artifact.LayerID].Vulnerabilities[entry.Vulnerability.ID]; !ok {
					val.Vulnerabilities[entry.Vulnerability.ID] = VulnerabilitySBOM{
						VulnID:    entry.Vulnerability.ID,
						Severity:  entry.Vulnerability.Severity,
						Locations: NewSet(),
						Artifacts: NewSet(),
					}
					val.Vulnerabilities[entry.Vulnerability.ID].Locations.Add(artifact.Path)
					val.Vulnerabilities[entry.Vulnerability.ID].Artifacts.Add(entry.Artifact.ID)
					switch strings.ToUpper(entry.Vulnerability.Severity) {
					case "CRITICAL":
						val.NumCritical++
					case "HIGH":
						val.NumHigh++
					case "MEDIUM":
						val.NumMedium++
					case "LOW":
						val.NumLow++
					case "INFO":
						val.NumInfo++
					}
					findings[artifact.LayerID] = val
				} else {
					if val.Vulnerabilities[entry.Vulnerability.ID].Artifacts.Has(entry.Artifact.ID) {
						break
					}
					val.Vulnerabilities[entry.Vulnerability.ID].Artifacts.Add(entry.Artifact.ID)
					switch strings.ToUpper(entry.Vulnerability.Severity) {
					case "CRITICAL":
						val.NumCritical++
					case "HIGH":
						val.NumHigh++
					case "MEDIUM":
						val.NumMedium++
					case "LOW":
						val.NumLow++
					case "INFO":
						val.NumInfo++
					}
					val.Vulnerabilities[entry.Vulnerability.ID].Locations.Add(artifact.Path)
					findings[artifact.LayerID] = val
				}
			}

		}
	}
	return &findings
}

type VulnerabilitySBOM struct {
	Locations *Set
	Artifacts *Set
	VulnID    string
	Severity  string
}

type SBOMFindings struct {
	NumCritical     int
	NumHigh         int
	NumMedium       int
	NumLow          int
	NumInfo         int
	Vulnerabilities map[string]VulnerabilitySBOM
}

type Set struct {
	list map[string]struct{} //empty structs occupy 0 memory
}

func (s *Set) Has(v string) bool {
	_, ok := s.list[v]
	return ok
}

func (s *Set) Add(v string) {
	s.list[v] = struct{}{}
}

func (s *Set) Remove(v string) {
	delete(s.list, v)
}

func (s *Set) Clear() {
	s.list = make(map[string]struct{})
}

func (s *Set) Size() int {
	return len(s.list)
}

func NewSet() *Set {
	s := &Set{}
	s.list = make(map[string]struct{})
	return s
}

//optional functionalities

// AddMulti Add multiple values in the set
func (s *Set) AddMulti(list ...string) {
	for _, v := range list {
		s.Add(v)
	}
}

type FilterFunc func(v string) bool

// Filter returns a subset, that contains only the values that satisfies the given predicate P
func (s *Set) Filter(P FilterFunc) *Set {
	res := NewSet()
	for v := range s.list {
		if P(v) == false {
			continue
		}
		res.Add(v)
	}
	return res
}

func (s *Set) Union(s2 *Set) *Set {
	res := NewSet()
	for v := range s.list {
		res.Add(v)
	}

	for v := range s2.list {
		res.Add(v)
	}
	return res
}

func (s *Set) Intersect(s2 *Set) *Set {
	res := NewSet()
	for v := range s.list {
		if s2.Has(v) == false {
			continue
		}
		res.Add(v)
	}
	return res
}

// Difference returns the subset from s, that doesn't exists in s2 (param)
func (s *Set) Difference(s2 *Set) *Set {
	res := NewSet()
	for v := range s.list {
		if s2.Has(v) {
			continue
		}
		res.Add(v)
	}
	return res
}

func (s *Set) ToString() string {
	return fmt.Sprintf("%v", s.list)
}
