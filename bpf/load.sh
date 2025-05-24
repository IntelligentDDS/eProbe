# compile kernel eBPF program

clang-10 -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -I. -c probe.bpf.c -o probe.bpf.o
bpftool gen skeleton probe.bpf.o > ../include/probe/probe.skel.h

# clang tracing.c -lbpf -lelf -o tracing

# ./tracing
