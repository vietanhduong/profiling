package syms

import (
	"fmt"
	"os"
	"runtime"

	"github.com/golang/glog"
	"github.com/vietanhduong/profiling/pkg/proc"
	"github.com/vietanhduong/profiling/pkg/syms/elf"
	"golang.org/x/sys/unix"
)

type vdsoStatus struct {
	image string
	err   error
}

var vstatus *vdsoStatus

func buildvDSOResolver() (SymbolTable, error) {
	if vstatus == nil {
		vstatus = &vdsoStatus{}
		vstatus.image, vstatus.err = findVDSO()
		runtime.SetFinalizer(vstatus, (*vdsoStatus).Cleanup)
		if vstatus.err != nil {
			return nil, vstatus.err
		}
	}

	if vstatus != nil && vstatus.err != nil {
		return nil, fmt.Errorf("vdso already failed before: %w", vstatus.err)
	}

	mf, err := elf.NewMMapedElfFile(vstatus.image)
	if err != nil {
		return nil, fmt.Errorf("open mmaped filed %s: %w, image, err", vstatus.image, err)
	}
	glog.V(5).Infof("Loaded vDSO (image=%s)", vstatus.image)
	return createSymbolTable(mf, &elf.SymbolOptions{
		DemangleOpts: DemangleFull.ToOptions(),
	}), nil
}

func findVDSO() (string, error) {
	pid := unix.Getpid()
	maps, err := proc.ParseProcMap(pid)
	if err != nil {
		return "", fmt.Errorf("parse proc map pid %d: %w", pid, err)
	}

	for _, m := range maps {
		if image := buildVDSOImage(m, pid); image != "" {
			return image, nil
		}
	}
	return "", fmt.Errorf("unable to create vDSO image")
}

func buildVDSOImage(procmap *proc.Map, pid int) string {
	if !isVDSO(procmap.Pathname) {
		return ""
	}

	size := procmap.EndAddr - procmap.StartAddr
	procmem := proc.HostProcPath(fmt.Sprintf("%d/mem", pid))
	mem, err := os.OpenFile(procmem, os.O_RDONLY, 0)
	if err != nil {
		glog.Warningf("Build vDSO Image: Failed to open file %s: %v", procmem, err)
		return ""
	}
	defer mem.Close()

	if _, err = mem.Seek(int64(procmap.StartAddr), 0); err != nil {
		glog.Warningf("Build vDSO Image: Failed to seek to address: %v", err)
		return ""
	}

	buf := make([]byte, size)
	if _, err = mem.Read(buf); err != nil {
		glog.Warningf("Build vDSO Image: Failed read mem: %v", err)
		return ""
	}
	tmpfile, err := os.CreateTemp("", fmt.Sprintf("profile_%d_vdso_image_*", pid))
	if err != nil {
		glog.Warningf("Build vDSO Image: Failed to create vsdo temp file: %v", err)
		return ""
	}
	defer tmpfile.Close()

	if _, err = tmpfile.Write(buf); err != nil {
		glog.Errorf("failed to write to vDSO image: %v", err)
	}
	return tmpfile.Name()
}

func (s *vdsoStatus) Cleanup() {
	if s == nil || s.image == "" {
		return
	}
	glog.Infof("Remove vDSO image: %s", s.image)
	os.Remove(s.image)
	s.err = nil
}
