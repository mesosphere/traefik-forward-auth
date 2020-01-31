package authorization

import (
	"log"
	"path/filepath"
)

func PathMatches(url, pattern string) bool {
	result, err := filepath.Match(pattern, url)
	if err != nil {
		log.Printf("pattern is invalid: %s", pattern)
	}
	return result
}
