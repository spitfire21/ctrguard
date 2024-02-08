package main

import (
	"testing"
)

func TestFindRunningImage(t *testing.T) {
	commands := map[string]string{
		"docker run --rm -i -t alpine /bin/sh --login": "alpine",
		"docker run --rm -i -t alpine /bin/sh":         "alpine",
		"docker run --rm -i -t alpine":                 "alpine",
		"docker run --rm --volume /var/run/docker.sock:/var/run/docker.sock --name Grype anchore/grype:latest $(ImageName):$(ImageTag)": "anchore/grype:latest",
	}

	for k, v := range commands {
		image := findRunningImage(k)
		if image != v {
			t.Errorf("Expected %s, got %s", v, image)
		}
	}
}
