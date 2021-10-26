package features

var (
	v3URLPatternMatching bool
)

func EnableV3URLPatternMatchin() {
	v3URLPatternMatching = true
}

func V3URLPatternMatchingEnabled() bool {
	return v3URLPatternMatching
}
