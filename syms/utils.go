package syms

func isVDSO(path string) bool {
	return path == "[vdso]"
}
