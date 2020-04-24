#!/usr/bin/env python3

from bcc import BPF
code = """
#include <uapi/linux/ptrace.h>

BPF_HASH(start, u64, u64);

int probe_handler(struct pt_regs *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	u64 pid = bpf_get_currect_pid_tgid();
	start.update(&pid, &ts);
	return 0;
}

int ret_handler(struct pt_regs *ctx)
{
	u64 ts = bpf_ktime_get_ns();
	u64 pid = bpf_get_currect_pid_tgid();
	u64 *tsp = (start.lookup(&pid));
	if (tsp) {
		bpf_trace_printk("%llu\\n", ts - *tsp);
		start.delete(&pid);
	}
	return 0;
}
"""

b = BPF(text = code)
b.attach_kprobe(event = "kthread_run", fn_name = "probe_handler")
b.attach_kretprobe(event = "kthread_run", fn_name = "ret_handler")
b.trace_print()
