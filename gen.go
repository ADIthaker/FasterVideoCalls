package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux sfu tc_kern.bpf.c -- -I./include -w
