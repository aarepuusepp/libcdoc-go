package libcdoc

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version is the library version, sourced from the VERSION file and embedded at build time.
var Version = strings.TrimSpace(versionFile)
