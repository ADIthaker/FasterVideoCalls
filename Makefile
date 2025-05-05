.PHONY: start-server clean plots build-ebpf build-server build-client results

start-server:
	cd sfu/server
	go build
	ifeq ($(MODE),ebpf)
		bash ./server --ebpf
	else
		bash ./server 
	endif

clean:
	echo "Cleaning Logs, Results and Captures..."
	bash ./results.sh clean
	echo "Fresh Testing Environment Setup"

build-ebpf:
	bash ./build
	ifeq ($(MODE),attach)
		./sfu_ebpf
	endif

build-server:
	cd sfu/server
	go build

build-client:
	cd sfu/client
	go build

results:
	ifneq ($(MODE), ebpf)
	ifneq ($(MODE), no-ebpf)
		$(error MODE is not set. Use: MODE=ebpf OR MODE=no-ebpf)
	endif
	endif
	ifeq ($(strip $(NO_CLIENTS)),)
		$(error NO_CLIENTS is not set. Use: NO_CLIENTS=3 or any other integer)
	CAPTURE_TIME
	ifeq ($(strip $(CAPTURE_TIME)),)
		$(error CAPTURE_TIME is not set. Use: CAPTURE_TIME=60 or any other integer in secs)
	endif
	ifeq ($(strip $(CLIENTS_TIME)),)
		$(error CLIENTS_TIME is not set. Use: CLIENTS_TIME=200 or any other integer in secs)
	endif
	echo "Running results with $(NO_CLIENTS) clients each running for $(CLIENTS_TIME) seconds, connected to a $(MODE) server and capturing packets for $(CAPTURE_TIME) seconds after allowing 30seconds of warmup"
	bash ./results $(CAPTURE_TIME) $(NO_CLIENTS) $(CLIENTS_TIME) $(MODE)

plots:
	echo "Make sure you have installed all deps from requirements.txt"
	mkdir -p plots
	python plots.py


