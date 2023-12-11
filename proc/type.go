package proc

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type Map struct {
	Pathname   string
	StartAddr  uint64
	EndAddr    uint64
	FileOffset uint
	DevMajor   uint32
	DevMinor   uint32
	Inode      uint64
	InMem      bool
}

func (m *Map) String() string {
	if m == nil {
		return ""
	}

	return fmt.Sprintf("%s 0x%016x-0x%016x 0x%016x %x:%x %d %t",
		m.Pathname,
		m.StartAddr,
		m.EndAddr,
		m.FileOffset,
		m.DevMajor,
		m.DevMinor,
		m.Inode,
		m.InMem)
}

type File struct {
	Dev   uint64
	Inode uint64
	Path  string
}

func (m *Map) File() File {
	return File{
		Inode: m.Inode,
		Path:  m.Pathname,
		Dev:   unix.Mkdev(m.DevMajor, m.DevMinor),
	}
}
