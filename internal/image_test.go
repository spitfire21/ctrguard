package internal

import (
	"context"
	"testing"
)

func TestNumOfLayers(t *testing.T) {
	images := map[string]int{
		"alpine":        1,
		"anchore/grype": 5,
	}
	for k, v := range images {
		if num := NumOfLayers(context.Background(), k); num != v {
			t.Errorf("Expected %d, got %d", v, num)
		}

	}

}
