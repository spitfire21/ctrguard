package image

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

func TestCompareImageLayers(t *testing.T) {
	layers1 := []string{"1", "2", "3"}
	layers2 := []string{"2", "3", "1"}
	if compare := CompareImageLayers(layers1, layers2); !compare {
		t.Errorf("Expected true, got %t", compare)
	}

	layers3 := []string{"1", "2", "3"}
	layers4 := []string{"2", "3", "4"}
	if compare := CompareImageLayers(layers3, layers4); compare {
		t.Errorf("Expected false, got %t", compare)
	}

	layers5 := []string{"1", "2", "3"}
	layers6 := []string{"1", "2", "3", "5"}

	if compare := CompareImageLayers(layers5, layers6); compare {
		t.Errorf("Expected false, got %t", compare)
	}
}
