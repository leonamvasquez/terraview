// Package assets embeds static files bundled into the terraview binary.
package assets

import _ "embed"

// LogoPNG is the terraview logo embedded at build time from assets/terraview-logo.png.
//
//go:embed terraview-logo.png
var LogoPNG []byte
