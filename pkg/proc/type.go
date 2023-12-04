package proc

import "fmt"

type ProcMap struct {
	Name       string
	StartAddr  uint64
	EndAddr    uint64
	FileOffset uint
	DevMajor   uint64
	DevMinor   uint64
	Inode      uint64
	Memfd      bool
}

func (pm *ProcMap) String() string {
	if pm == nil {
		return ""
	}

	return fmt.Sprintf("%s 0x%016x-0x%016x 0x%016x %x:%x %d %t",
		pm.Name,
		pm.StartAddr,
		pm.EndAddr,
		pm.FileOffset,
		pm.DevMajor,
		pm.DevMinor,
		pm.Inode,
		pm.Memfd)
}
