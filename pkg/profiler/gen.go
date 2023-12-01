package profiler

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type stack_t -target amd64 -cc clang -cflags "-O2 -Wall -Werror -fpie -Wno-unused-variable -Wno-unused-function" Profiler ../../bpf/profiler.bpf.c -- -I../../bpf/libbpf -I../../bpf/vmlinux
