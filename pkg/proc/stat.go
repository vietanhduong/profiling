package proc

import (
	"fmt"
	"os"
	"syscall"

	"github.com/golang/glog"
	"golang.org/x/sys/unix"
)

type Stat struct {
	procfs         string
	rootSymlink    string
	mountNsSymlink string
	// file descriptor of /proc/<pid>/root open with O_PATH used to get into root
	// of process after it exits; unlike a dereferenced root symlink, *at calls
	// to this use the process's mount namespace
	rootFd int
	// store also root path and mount namespace pair to detect its change
	root    string
	mountNs string

	inode uint64
}

func ProcStat(pid int) (*Stat, error) {
	stat := &Stat{
		procfs:         HostProcPath(fmt.Sprintf("%d/exe", pid)),
		rootSymlink:    HostProcPath(fmt.Sprintf("%d/root", pid)),
		mountNsSymlink: HostProcPath(fmt.Sprintf("%d/ns/mnt", pid)),
		rootFd:         -1,
	}
	var err error
	if stat.inode, err = getinode(stat.procfs); err != nil {
		return nil, fmt.Errorf("get inode: %w", err)
	}
	stat.RefreshRoot()
	return stat, nil
}

func (s *Stat) RefreshRoot() bool {
	// Try to get current root and current mount namespace for the process
	// If an error is raise, that means the process might not exists anymore;
	// keep the old fd
	currentRoot, err := os.Readlink(s.rootSymlink)
	if err != nil {
		return false
	}
	currentMountNs, err := os.Readlink(s.mountNsSymlink)
	if err != nil {
		return false
	}
	// Check if the root FD is up-to-date
	if s.rootFd != -1 && s.root == currentRoot && s.mountNs == currentMountNs {
		return false
	}
	s.root = currentRoot
	s.mountNs = currentMountNs
	oldFd := s.rootFd
	s.rootFd, err = unix.Open(s.rootSymlink, unix.O_PATH, 0)
	if err != nil {
		glog.Warningf("Failed to open %s: %v", s.rootSymlink, err)
	}
	if oldFd > 0 {
		syscall.Close(oldFd)
	}
	return s.rootFd != oldFd
}

func (s *Stat) GetRootFD() int { return s.rootFd }

func (s *Stat) IsStale() bool {
	inode, _ := getinode(s.procfs)
	return inode != s.inode && s.RefreshRoot()
}

func (s *Stat) Reset() { s.inode, _ = getinode(s.procfs) }

func getinode(procfs string) (uint64, error) {
	var stat unix.Stat_t
	if err := unix.Stat(procfs, &stat); err != nil {
		return 0, fmt.Errorf("unix stat %s: %w", procfs, err)
	}
	return stat.Ino, nil
}
