#!/bin/bash


mkdir -p results
mkdir -p captures
mkdir -p logs
mkdir -p logs/server

if [ "$1" == "clean" ]; then
    rm -rf results
    rm -rf logs
    rm -rf captures
    exit 0
fi

#args
capture_time=$1
no_clients=$2
clients_time=$3
is_ebpf=$4



#Files
file_id="${capture_time}_${no_clients}_${clients_time}_${is_ebpf}"

#Server logs
server_log="logs/server/${file_id}.log"

#Client logs
client_log_suffix="${file_id}"


if [ "$is_ebpf" == "ebpf" ]; then
    echo "Building ebpf program..."
    ./build
    echo "Attaching ebpf program..."
    ./sfu_ebpf > /dev/null 2>&1 &
    ebpf_pid=$!
    if [ $? -eq 0 ]; then 
        echo "Starting server..."
        ./sfu/server/server --ebpf > $server_log 2>&1 &
        server_start=$?
        server_pid=$!
    else
        exit 1
    fi
else
    echo "Starting server..."
    ./sfu/server/server > $server_log 2>&1 &
    server_start=$?
    server_pid=$!

fi


start=$(date +%s)
if [ $server_start -eq 0 ]; then
    python3 sfu/benchmark.py $no_clients $clients_time $client_log_suffix &
    benchmark_pid=$!
else
    echo "Server didn't start, check logs at ${server_log}"
    exit 1
fi

echo "Waiting 30secs for clients to connect..."
sleep 30

# Capture packets
capture_file="results/report_${file_id}.pcap"

timeout $capture_time tshark -i lo -f "udp and not port 5353 and not port 3478 and not port 53 and not port 123 and not stun" -w $capture_file

# Get conversations stats
tshark -r $capture_file -q -z conv,udp > "results/${file_id}_conversations.txt"

# Get RTP stats
tshark -r $capture_file -o rtp.heuristic_rtp:TRUE -Y rtp -q -z rtp,streams > "results/${file_id}_rtp.txt"

wait_time=$(( clients_time  + 10 ))

while true; do
    now=$(date +%s)
    if [ $(( now - start )) -ge $wait_time ]; then
        echo "Clients are done"
        kill -9 $server_pid 
        kill -9 $benchmark_pid
        kill -9 $ebpf_pid
        break
    fi
    sleep 5
done








