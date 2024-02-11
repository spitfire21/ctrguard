package scan

type Layer struct {
	id       string
	severity string
}

type ImageScanInfo struct {
	Name   string
	Layers []Layer
}

type Metrics struct {
	baseScore           float64
	impactScore         float64
	exploitabilityScore float64
}

type Cvss struct {
	source         string
	type_          string
	version        string
	vector         string
	metrics        Metrics
	vendorMetadata interface{}
}
type Fix struct {
	versions []string
	state    string
}
type Vulnerability struct {
	id          string
	dataSource  string
	namespace   string
	severity    string
	urls        []string
	description string
	cvss        []string
	advistories []string
}
type Package struct {
	name    string
	version string
}
type MatchDetails struct {
	type_      string
	matcher    string
	searchedBy interface{}
	found      interface{}
	namespace  string
	package_   Package
}

type ArtifactLocation struct {
	path    string
	layerID string
}

type Artifact struct {
	id       string
	name     string
	version  string
	type_    string
	location ArtifactLocation
}

type Match struct {
	Vulnerability          Vulnerability
	RelatedVulnerabilities []Vulnerability
	Description            string
	Cvss                   Cvss
	Fix                    Fix
	MatchDetails           MatchDetails
	Artifact               Artifact
}

type ScanInfo struct {
	Matches []ImageScanInfo
}
type Entry struct {
}

type Stream struct {
	Stream chan Entry
}

func LoadScan(path string) {
	return
}
