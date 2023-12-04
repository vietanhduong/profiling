package proc

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/golang/glog"
)

func ParseProcMap(pid int) ([]*ProcMap, error) {
	mapfile := HostProcPath(fmt.Sprintf("%d", pid), "maps")
	f, err := os.Open(mapfile)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", mapfile, err)
	}
	defer f.Close()

	ret, err := parseProcMap(f, pid)
	if err != nil {
		glog.Warning("Failed to parse proc map %s: %v", mapfile, err)
	}

	if mappath := FindPerfMapPath(pid); mappath != "" {
		ret = append(ret, &ProcMap{Name: mappath})
	}

	if mappath := fmt.Sprintf("/tmp/perf-%d.map", pid); len(mappath) < 4096 &&
		!containsPath(ret, mappath) {
		ret = append(ret, &ProcMap{Name: mappath})
	}
	return ret, nil
}

func FindPerfMapPath(pid int) string {
	rootpath := HostProcPath(fmt.Sprintf("%d/root", pid))
	target, err := os.Readlink(rootpath)
	if err != nil {
		return ""
	}
	if nstigd := FindPerfMapNStgid(pid); nstigd != -1 {
		return filepath.Join(target, fmt.Sprintf("tmp/perf-%d.map", nstigd))
	}
	return ""
}

func FindPerfMapNStgid(pid int) int {
	nstgid := -1
	statuspath := HostProcPath(fmt.Sprintf("%d/status", pid))
	f, err := os.Open(statuspath)
	if err != nil {
		return nstgid
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// check Tgid line first in case CONFIG_PID_NS is off
		if strings.HasPrefix(line, "Tgid:") {
			nstgid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Tgid:")))
		}
		// PID namespaces can be nested -- last number is innermost PID
		if strings.HasPrefix(line, "NStgid:") {
			nstgid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "NStgid:")))
		}
	}
	if err = scanner.Err(); err != nil {
		return -1
	}
	return nstgid
}

func parseProcMap(f *os.File, pid int) ([]*ProcMap, error) {
	var ret []*ProcMap
	for {
		var m ProcMap
		var perm, buf string
		n, _ := fmt.Fscanf(f, "%x-%x %4s %x %x:%x %d %s\n",
			&m.StartAddr,
			&m.EndAddr,
			&perm,
			&m.FileOffset,
			&m.DevMajor,
			&m.DevMinor,
			&m.Inode,
			&buf)
		if n > 8 || n < 7 {
			break
		}

		if len(perm) != 4 || perm[2] != 'x' { // executable only
			continue
		}
		m.Name = strings.TrimSpace(buf)

		if isFileBacked(m.Name) {
			continue
		}

		var resolved string
		if strings.Contains(m.Name, "/memfd:") {
			if resolved = findMemFdPath(pid, m.Inode); resolved != "" {
				m.Memfd = true
			}
		}
		// TODO(vietanhduong): handle zip and apk

		if resolved != "" {
			m.Name = resolved
		}
		ret = append(ret, &m)
	}
	return ret, nil
}

func isFileBacked(mapname string) bool {
	return mapname != "" && (strings.HasPrefix(mapname, "//anon") ||
		strings.HasPrefix(mapname, "/dev/zero") ||
		strings.HasPrefix(mapname, "/anon_hugepage") ||
		strings.HasPrefix(mapname, "[stack") ||
		strings.HasPrefix(mapname, "/SYSV") ||
		strings.HasPrefix(mapname, "[heap]") ||
		strings.HasPrefix(mapname, "[vsyscall]"))
}

func findMemFdPath(pid int, inode uint64) string {
	var ret string
	fdpath := HostProcPath(fmt.Sprintf("%d/%d", pid, inode))
	err := filepath.Walk(fdpath, func(path string, info fs.FileInfo, err error) error {
		if ret != "" {
			return nil
		}
		stats, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		if stats.Ino == inode {
			ret = path
		}
		return nil
	})
	if err != nil {
		glog.Warning("Failed to walk at dir %s: %v", fdpath, err)
	}
	return ret
}

func containsPath(maps []*ProcMap, path string) bool {
	for _, m := range maps {
		if path == m.Name {
			return true
		}
	}
	return false
}
