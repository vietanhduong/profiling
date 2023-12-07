package syms

import (
	"strings"

	"golang.org/x/sys/unix"
)

func isPerfMap(path string) bool {
	return strings.HasSuffix(path, ".map")
}

func isValidPerfMap(path string) bool {
	return isPerfMap(path) && unix.Access(path, unix.R_OK) == nil
}

func isVDSO(path string) bool { return path == "[vdso]" }
