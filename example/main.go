package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/golang/glog"
	"github.com/samber/lo"
	"github.com/vietanhduong/profiling/example/profiler"
	"github.com/vietanhduong/profiling/perf"
	"github.com/vietanhduong/profiling/ring"
	"github.com/vietanhduong/profiling/syms"
)

func main() {
	var pid int
	var sampleRate int
	var pollPeriod time.Duration
	flag.IntVar(&pid, "pid", -1, "Target observe Process ID")
	flag.IntVar(&sampleRate, "sample-rate", 49, "Sample rate (unit Hz). Should be 49, 99.")
	flag.DurationVar(&pollPeriod, "poll-period", 30*time.Second, "The duration between polling data from epoll.")
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
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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
		SampleRate: uint64(sampleRate),
	})
	if err != nil {
		glog.Errorf("Failed to attach perf event: %v", err)
		os.Exit(1)
	}
	defer perfevent.Close()

	procResolver, err := syms.NewResolver(pid, nil)
	if err != nil {
		glog.Errorf("Failed to new symbol resolver with PID %d: %v", pid, err)
		os.Exit(1)
	}
	defer procResolver.Cleanup()

	kernResolver, err := syms.NewResolver(-1, nil)
	if err != nil {
		glog.Errorf("Failed to new kernel resolver: %v", err)
		os.Exit(1)
	}
	defer kernResolver.Cleanup()

	getstack := func(stackid int64) []byte {
		if stackid < 0 {
			return nil
		}
		res, err := objs.StackTraces.LookupBytes(uint32(stackid))
		if err != nil {
			glog.Errorf("Err: Failed to lookup stackid 0x%08x", stackid)
			return nil
		}
		return res
	}

	callback := func(raw []byte) {
		stack := (*profiler.ProfilerStackT)(unsafe.Pointer(&raw[0]))
		if stack.Pid != uint32(pid) {
			return
		}
		builder := &stackbuilder{}
		buildStack(builder, "", getstack(int64(stack.UserStackId)), procResolver)
		buildStack(builder, "[k] ", getstack(int64(stack.KernelStackId)), kernResolver)
		if len(builder.stacks) == 0 {
			return
		}
		lo.Reverse(builder.stacks)
		glog.V(10).Infof("trace: %s", strings.Join(builder.stacks, ";"))
	}

	reader, err := ring.NewReader(objs.Histogram, ring.Spec{
		Callback: callback,
	})
	if err != nil {
		glog.Errorf("Failed to open ring buffer: %v", err)
		os.Exit(1)
	}
	defer reader.Close()

	glog.Infof("Waiting for event...")
	ticker := time.NewTicker(pollPeriod)
	for {
		select {
		case <-ctx.Done():
			glog.Infof("Received signal, exiting...")
			return
		case <-ticker.C:
			count, err := reader.Poll(0)
			if err != nil {
				glog.Errorf("Failed to open ring buffer: %v", err)
				os.Exit(1)
			}
			glog.V(12).Infof("Total polled records: %d", count)
			glog.Infof("Wait 30s before poll again...")
		}
	}
}

func buildStack(builder *stackbuilder, prefix string, stack []byte, resolver syms.Resolver) {
	if len(stack) == 0 {
		return
	}
	var stackFrames []string
	for i := 0; i < 127; i++ {
		instructionPointerBytes := stack[i*8 : i*8+8]
		ins := binary.LittleEndian.Uint64(instructionPointerBytes)
		if ins == 0 {
			break
		}
		sym := resolver.Resolve(ins)
		var name string
		if sym.Name != "" {
			name = sym.Name
		} else {
			if sym.Module != "" {
				name = fmt.Sprintf("%s+%x", sym.Module, sym.Start)
			} else {
				name = fmt.Sprintf("%x", ins)
			}
		}
		stackFrames = append(stackFrames, fmt.Sprintf("%s%s", prefix, name))
	}
	lo.Reverse(stackFrames)
	for _, s := range stackFrames {
		builder.append(s)
	}
}

type stackbuilder struct {
	stacks []string
}

func (sb *stackbuilder) append(stack string) { sb.stacks = append(sb.stacks, stack) }
