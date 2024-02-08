package internal

import (
	"context"

	"github.com/docker/docker/client"
	"github.com/google/martian/log"
)

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
	return true
}
