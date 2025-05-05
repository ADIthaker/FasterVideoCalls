import subprocess
import threading
import time
import os
import re
import sys

# first_rtp_ms:
# Time (in milliseconds) from starting the connection to receiving the first RTP packet.
# Lower values indicate faster media pipeline setup.

# max_bitrate_kbps:
# Maximum bitrate (in kilobits per second) observed during the session.
# Indicates how much media data was successfully received over time.

# max_packets:
# Maximum number of RTP packets received per second.
# Useful for detecting packet flow consistency and performance bottlenecks.

# Note: These metrics are parsed from client log lines like:
# - 📦 Time to First RTP: 112.43ms
# - 📈 Packets: 42/s | Bitrate: 910.25 kbps
# --- CONFIG ---
CLIENT_BINARY = "sfu/client/client"
TOTAL_CLIENTS = int(sys.argv[1])
RUN_DURATION = int(sys.argv[2])  # seconds
LOG_PREFIX = sys.argv[3]
LOG_DIR = "logs/client"
os.makedirs(LOG_DIR, exist_ok=True)

results = []
failed = []

def run_client(index):
    log_file = os.path.join(LOG_DIR, f"{LOG_PREFIX}_client_{index}.log")
    with open(log_file, "w") as f:
        try:
            print(f"[Client-{index}] 🚀 Starting")
            proc = subprocess.run([CLIENT_BINARY, f"--duration={RUN_DURATION}"], stdout=f, stderr=subprocess.STDOUT, timeout=RUN_DURATION+10)
            if proc.returncode == 0:
                print(f"[Client-{index}] ✅ Success")
            else:
                print(f"[Client-{index}] ❌ Return code: {proc.returncode}")
                failed.append(index)
        except subprocess.TimeoutExpired:
            print(f"[Client-{index}] ❌ Timeout")
            failed.append(index)

def parse_metrics(index):
    log_file = os.path.join(LOG_DIR, f"client-{index}.log")
    metrics = {
        "client": index,
        "first_rtp_ms": None,
        "max_bitrate_kbps": 0.0,
        "max_packets": 0
    }

    with open(log_file, "r") as f:
        for line in f:
            if "Time to First RTP" in line:
                match = re.search(r"([0-9.]+)\s*ms", line)
                if match:
                    metrics["first_rtp_ms"] = float(match.group(1))
            elif "Bitrate:" in line:
                match = re.search(r"Bitrate:\s*([0-9.]+)\s*kbps", line)
                if match:
                    bitrate = float(match.group(1))
                    metrics["max_bitrate_kbps"] = max(metrics["max_bitrate_kbps"], bitrate)
            if "Packets:" in line:
                match = re.search(r"Packets:\s*([0-9]+)/s", line)
                if match:
                    pps = int(match.group(1))
                    metrics["max_packets"] = max(metrics["max_packets"], pps)
    return metrics

def run_benchmark():
    threads = []

    for i in range(TOTAL_CLIENTS):
        t = threading.Thread(target=run_client, args=(i,))
        threads.append(t)
        t.start()
        time.sleep(0.1)  # stagger startup

    for t in threads:
        t.join()

    # print("\n=== Benchmark Results ===")
    # for i in range(TOTAL_CLIENTS):
    #     if i in failed:
    #         continue
    #     m = parse_metrics(i)
    #     results.append(m)
    #     print(f"[Client-{m['client']}] RTP: {m['first_rtp_ms']}ms | Max Bitrate: {m['max_bitrate_kbps']} kbps | Max Packets/s: {m['max_packets']}")

    # print(f"\n✅ Successful Clients: {len(results)} / {TOTAL_CLIENTS}")
    # if results:
    #     avg_rtp = sum(r['first_rtp_ms'] for r in results if r['first_rtp_ms']) / len(results)
    #     avg_bitrate = sum(r['max_bitrate_kbps'] for r in results) / len(results)
    #     avg_pps = sum(r['max_packets'] for r in results) / len(results)

    #     print(f"\n📊 Averages:\n - First RTP: {avg_rtp:.2f}ms\n - Bitrate: {avg_bitrate:.2f} kbps\n - Packets/s: {avg_pps:.2f}")

if __name__ == "__main__":
    if not os.path.exists(CLIENT_BINARY):
        print("❌ Client binary not found. Run `go build -o client client.go` first.")
    else:
        run_benchmark()
