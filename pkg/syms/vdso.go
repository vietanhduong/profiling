package syms

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/golang/glog"
	"github.com/vietanhduong/profiling/pkg/proc"
	"github.com/vietanhduong/profiling/pkg/syms/elf"
)

//#include <string.h>
import "C"

type vdsoStatus struct {
	image string
	err   error
}

var vstatus *vdsoStatus

func CreateVDSOResolver(pid int) (SymbolTable, error) {
	if vstatus == nil {
		vstatus = &vdsoStatus{}
		vstatus.image, vstatus.err = findVDSO(pid)
		if vstatus.err != nil {
			return nil, vstatus.err
		}
	}

	if vstatus != nil && vstatus.err != nil {
		return nil, fmt.Errorf("vdso already failed before: %w", vstatus.err)
	}

	mf, err := elf.NewMMapedFile(vstatus.image)
	if err != nil {
		return nil, fmt.Errorf("open mmaped filed %s: %w, image, err", vstatus.image, err)
	}

	return createSymbolTable(mf, &elf.SymbolOptions{
		DemangleOpts: DemangleFull.ToOptions(),
	}), nil
}

func findVDSO(pid int) (string, error) {
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
	buf := make([]byte, 0, size)

	C.memcpy(unsafe.Pointer(&buf[0]), unsafe.Pointer(&procmap.StartAddr), C.size_t(size))

	tmpfile, err := os.CreateTemp("", fmt.Sprintf("profile_%d_vdso_image_XXXXXX", pid))
	if err != nil {
		glog.Warning("Failed to create vsdo temp file: %v", err)
		return ""
	}
	defer tmpfile.Close()

	if _, err = tmpfile.Write(buf); err != nil {
		glog.Errorf("failed to write to vDSO image: %v", err)
	}
	return tmpfile.Name()
}
