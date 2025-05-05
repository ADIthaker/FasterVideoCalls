# eBPF-Accelerated Video Conferencing (SFU Server)

This project is a high-performance **Selective Forwarding Unit (SFU)** written in Go using [Pion WebRTC](https://github.com/pion/webrtc), accelerated with **eBPF** via TC ingress hooks for low-latency RTP packet redirection.

---

## Features

- A simple implementation WebRTC SFU server in Go (Pion)
- Optional eBPF support via TC ingress hook
- Efficient forwarding of RTP packets
- ICE connection-aware eBPF map management
- Dynamic insertion/removal of client addresses from eBPF
- Built-in benchmarking support using tshark and iperf

---

## Project Structure

```
sfu_ebpf/
├── include/            # Includes helper C headers
├── logs/               # Stores server and client logs during results
├── results/            # Stores .pcap files, and conversations, rtp_streams txt files.
├── sfu/                # Client WebRTC example
    ├── client
        ├── main.go           # SFU client code
    ├── server
        ├── main.go           # SFU server code
    ├── benchmark.py          # Creates clients for a running server by taking in number of clients, time-to-live, client-log-suffix.
├── main.go             # eBPF program loading logic
├── build               # Build script to build after changing the eBPF C file, main.go; creates sfu_ebpf binary that loads and prints the eBPF participant maps.
├── gen.go              # go:generate script for compiling eBPF
├── tc_kern.bpf.c       # eBPF TC program
├── results.sh          # Builds and breaks server for ebpf/no-ebpf, runs benchmark.py for clients, and starts capturing packets which are then written as conversations and streams in results.


```

---

## How eBPF is used

- Go server accepts WebRTC offers and negotiates connections.
- On ICE connection establishment, it extracts the client's IP and port.
- These values are inserted into an eBPF array map (`xdp_ip_tc_map`) with a fixed index allocator.
- The eBPF TC program matches UDP RTP packets and clones/forwards them to all clients in the map.
- When a client disconnects, its entry is zeroed out in the map.

---

## Running the Server

### 1. Generate eBPF bindings

```bash
go mod tidy
go generate
```

### 2. Build and run

```bash
./build
cd sfu/server
go build
./sfu_server --ebpf      # With eBPF acceleration
./sfu_server             # Without eBPF, fallback to Go-level forwarding
```

### 3. Connecting using clients
```bash
cd sfu/client
go build
./client --duration <secs>      # Clients runs for <secs> seconds.
./client                    # Clients runs for 30 seconds.
```

---

## Benchmarking

Use `tshark` to measure latency, packet count, jitter, and throughput:

```bash
tshark -i lo -Y rtp -T fields \
  -e frame.time_relative -e ip.src -e ip.dst -e rtp.seq -e rtp.timestamp \
  -E separator=, -E header=y > rtp_trace.csv
```

Use `-z conv,udp` for UDP conversation summary.

OR
Use `./results.sh <capture_time> <no_of_clients> <client_ttl> <type>`
Here:
1. capture_time: How long should you capture packets?
2. no_of_clients: How many clients to use?
3. client_ttl: How long should each client live (in seconds)?
4. type: 'no-ebpf' - for vanilla SFU server; 'ebpf' - to enable ebpf powered sfu.

---

## Prerequisites

- Linux with kernel 6.0+
- clang/llvm toolchain
- eBPF development libraries, find them [here](https://github.com/xdp-project/xdp-tutorial/blob/main/setup_dependencies.org#packages-on-debianubuntu)
- `tc`, `bpftool`, `tshark`
- Go 1.21+
- Port 8080 open (or adjust in code)

---
