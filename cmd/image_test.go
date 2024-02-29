package main

import (
	"testing"
)

func TestFindRunningImage(t *testing.T) {
	commands := map[string][]string{
		"docker run --rm -i -t alpine /bin/sh --login": []string{"alpine"},
		"docker run --rm -i -t alpine /bin/sh":         []string{"alpine"},
		"docker run --rm -i -t alpine":                 []string{"alpine"},
		"docker run --rm --volume /var/run/docker.sock:/var/run/docker.sock --name Grype anchore/grype:latest $(ImageName):$(ImageTag)": []string{"anchore/grype", "latest"},
	}

	for k, v := range commands {
		image, version := findRunningImage(k)
		if image != v[0] {
			t.Errorf("Expected %s, got %s", v, image)
		}
		if len(v) > 1 && version != v[1] {
			t.Errorf("Expected %s, got %s", v, version)
		}
	}
}
