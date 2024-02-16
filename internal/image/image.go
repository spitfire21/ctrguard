package image

import (
	"context"
	"sort"

	"github.com/docker/docker/client"
	"github.com/google/martian/log"
)

type LayerVuln struct {
	LayerID         string
	Vulnerabilities map[string]int
}

func NumOfLayers(ctx context.Context, image string) int {
	apiClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Errorf("")
	}
	apiClient.NegotiateAPIVersion(ctx)
	imageInspect, _, err := apiClient.ImageInspectWithRaw(ctx, image)

	if err != nil {
		log.Errorf("Error inspecting image: %s", err)
	}
	layerNum := len(imageInspect.RootFS.Layers)
	log.Infof("Number of layers: %d", layerNum)
	return layerNum
}

func CompareImageLayers(layers1, layers2 []string) bool {

	if len(layers1) != len(layers2) {
		return false
	}

	sort.Strings(layers1)
	sort.Strings(layers2)
	for i := 0; i < len(layers1); i++ {
		if layers1[i] != layers2[i] {
			return false
		}
	}

	return true
}
func CompareNumberOfLayers(image1 []string, image2 []string) int {
	// Math.Abs takes a float and returns a float
	// I will just calculate the difference manually
	// Absolute difference calculation
	x := len(image1)
	y := len(image2)
	if x < y {
		return y - x
	}
	return x - y
}
