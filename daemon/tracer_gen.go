package main

//go:generate bpf2go -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" tracer ../kernel/tracer.bpf.c -- -I../kernel
