package proc

import (
	"flag"
	"fmt"
	"path"
)

var (
	procPath = flag.String("proc-path", "/proc", "Path to proc directory")
	hostPath = flag.String("host-path", "/", "The host directory. Useful in container.")
)

func ProcPath(paths ...string) string {
	p := append([]string{*procPath}, paths...)
	return path.Join(p...)
}

func HostProcPath(paths ...string) string {
	if *hostPath == "" || *hostPath == "/" {
		return ProcPath(paths...)
	}
	p := append([]string{*hostPath, *procPath}, paths...)
	return path.Join(p...)
}

func HostPath(paths ...string) string {
	if *hostPath == "" {
		*hostPath = "/"
	}
	p := append([]string{*hostPath}, paths...)
	return path.Join(p...)
}

func ProcRoot(pid int) string {
	return ProcPath(fmt.Sprintf("%d/root", pid))
}

func HostProcRoot(pid int) string {
	return HostProcPath(fmt.Sprintf("%d/root", pid))
}
