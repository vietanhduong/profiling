# Profiling

A demonstration on implementing eBPF for profiling applications. This repository is inspired by BCC and Grafana/Pyroscope, with some customizations.
### ⚠️ Deprecation: This repository has been moved to [wBPF](https://github.com/vietanhduong/wbpf) and is no longer actively maintained.

## Notes

- This program requires a minimum Kernel Version of `5.8` because it is using a `Ring Buffer` to submit stack trace data.

## Uasge

```console
$ profiler -h

Usage of profiler:
  -alsologtostderr
        log to standard error as well as files
  -host-path string
        The host directory. Useful in container. (default "/")
  -log_backtrace_at value
        when logging hits line file:N, emit a stack trace
  -log_dir string
        If non-empty, write log files in this directory
  -log_link string
        If non-empty, add symbolic links in this directory to the log files
  -logbuflevel int
        Buffer log messages logged at this level or lower (-1 means don't buffer; 0 means buffer INFO only; ...). Has limited applicability on non-prod platforms.
  -logtostderr
        log to standard error instead of files
  -pid int
        Target observe Process ID (default -1)
  -poll-period duration
        The duration between polling data from epoll. (default 30s)
  -proc-path string
        Path to proc directory (default "/proc")
  -sample-rate int
        Sample rate (unit Hz). Should be 49, 99. (default 49)
  -stderrthreshold value
        logs at or above this threshold go to stderr (default 2)
  -v value
        log level for V logs
  -vmodule value
        comma-separated list of pattern=N settings for file-filtered logging
```
