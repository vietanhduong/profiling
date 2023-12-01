package main

import (
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/golang/glog"
	"github.com/vietanhduong/profiling/pkg/perf"
	"github.com/vietanhduong/profiling/pkg/profiler"
)

func main() {
	var pid int
	flag.IntVar(&pid, "pid", -1, "Target process id")
	flag.Parse()

	if pid == -1 {
		glog.Errorf("No pid is specified")
		os.Exit(1)
	}

	glog.Infof("Target observe PID %d", pid)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		glog.Errorf("Failed to remove memlock: %v", err)
		os.Exit(1)
	}

	// Subscribe to signals for terminating the program.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	var objs profiler.ProfilerObjects
	if err := profiler.LoadProfilerObjects(&objs, nil); err != nil {
		glog.Errorf("Failed to load profiler: %v", err)
		os.Exit(1)
	}
	defer objs.Close()

	btf.FlushKernelSpec()

	perfevent := perf.New()
	err := perfevent.AttachPerfEvent(&perf.AttachPerfEventSpec{
		Prog:       objs.DoPerfEvent,
		SampleRate: 11,
	})
	if err != nil {
		glog.Errorf("Failed to attach perf event: %v", err)
		os.Exit(1)
	}
	defer perfevent.Close()

	ring, err := ringbuf.NewReader(objs.Histogram)
	if err != nil {
		glog.Errorf("Failed to open ring buffer: %v", err)
		os.Exit(1)
	}
	defer ring.Close()

	go func() {
		<-stop
		if err := ring.Close(); err != nil {
			glog.Errorf("Failed to close ring buffer: %v", err)
		}
	}()

	glog.Infof("Waiting for event...")
	for {
		record, err := ring.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				glog.Infof("Received signal, exiting...")
				return
			}
			glog.Errorf("Failed to read data from ring: %v", err)
			continue
		}

		stack := (*profiler.ProfilerStackT)(unsafe.Pointer(&record.RawSample[0]))
		glog.Infof("Receiving stack trace from PID: %d", stack.Pid)
	}
}
