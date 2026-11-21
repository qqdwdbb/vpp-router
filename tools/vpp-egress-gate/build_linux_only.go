//go:build !linux

package gate

// A clearer failure than the undefined names that would follow. This file sorts
// before them, so its error comes first.
var _ = this_program_only_supports_Linux__build_with_make_or_GOOS_linux
