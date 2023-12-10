package syms

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/vietanhduong/profiling/proc"
	"golang.org/x/sys/unix"
)

type modulePath struct {
	path         string
	procRootPath string
	fd           int
}

func newModulePath(path string, pid, rootfd int, memfd bool) *modulePath {
	this := &modulePath{}
	if memfd {
		this.path = path
		this.procRootPath = path
		return this
	}

	this.procRootPath = proc.HostProcPath(fmt.Sprintf("%d/root", pid), path)
	trimmedPath := strings.TrimPrefix(filepath.Join(path), "/")
	var err error
	this.fd, err = unix.Openat(rootfd, trimmedPath, unix.O_RDONLY, 0)
	if err == nil {
		this.path = proc.HostProcPath(fmt.Sprintf("self/fd/%d", this.fd))
		runtime.SetFinalizer(this, (*modulePath).Close)
	} else {
		this.path = this.procRootPath
	}
	return this
}

func (p *modulePath) GetPath() string {
	if p.path == p.procRootPath || unix.Access(p.procRootPath, unix.F_OK) != nil {
		return p.path
	}
	return p.GetRootPath()
}

func (p *modulePath) GetRootPath() string { return p.procRootPath }

func (p *modulePath) Close() { syscall.Close(p.fd) }
