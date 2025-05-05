package main

import (
    "log"
    "net"
    "os"
    "math/bits"
    "os/signal"
    "time"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)
func pinMap(mapObj *ebpf.Map, path string) error {
    // First, remove old pin if it exists
    if _, err := os.Stat(path); err == nil {
        log.Printf("Removing existing pin at %s", path)
        if err := os.Remove(path); err != nil {
            return err
        }
    }

    // Now pin the map
    return mapObj.Pin(path)
}
func IntToIP(ip uint32) net.IP {
	result := make(net.IP, 4)
	result[0] = byte(ip)
	result[1] = byte(ip >> 8)
	result[2] = byte(ip >> 16)
	result[3] = byte(ip >> 24)
	return result
}
func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }

    // Load the compiled eBPF ELF and load it into the kernel.
    var objs sfuObjects 
    if err := loadSfuObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close() 

    ifname := "enp0s3" 
    iface, err := net.InterfaceByName(ifname)
    println(ifname)
    if err != nil {
        log.Fatalf("Getting interface %s: %s", ifname, err)
    }

    // Attach count_packets to the network interface.
    options := link.TCXOptions{ 
        Program:   objs.TcSfu,
        Interface: iface.Index,
        Attach: ebpf.AttachTCXIngress,
    }
    link, err := link.AttachTCX(options)
    if err != nil {
        log.Fatal("Attaching TC: ", err)
    } 
    defer link.Close() 

    log.Printf("Printing all connected users on %s..", ifname)

    // Periodically fetch the packet counter from PktCount,
    // exit the program when interrupted.
    tick := time.Tick(time.Second)
    stop := make(chan os.Signal, 5)
    signal.Notify(stop, os.Interrupt)
    shouldAdd := false
    err = pinMap(objs.XdpIpTcMap, "/sys/fs/bpf/xdp_ip_tc_map")
    if err != nil {
        log.Fatalf("Failed to pin map: %v", err)
    }
    for i := uint32(0); i < 10; i++ {
        objs.XdpIpTcMap.Put(i, &sfuIpRecord{})
    }
    for {
        select {
        case <-tick:
            entries := objs.XdpIpTcMap.Iterate() 
            var count sfuIpRecord
            var key uint32
            for  entries.Next(&key, &count){
                // err := objs.XdpIpTcMap.Lookup(uint32(0), &count) 
                if err != nil {
                    log.Fatal("Map lookup:", err)
                }
                ip := IntToIP(bits.ReverseBytes32(count.ParticipantIp)).String()
                port := bits.ReverseBytes16(count.ParticipantPort)
                log.Printf("Curent Participant IP %s, Current Participant Port %d", ip, port)
            } 
            log.Printf("--------------------------------Iteration-------------------------")
            if err := entries.Err(); err != nil {
                log.Fatal("Iterator encountered an error: ", err)
            }
            if shouldAdd {
                var newUser = sfuIpRecord {
                    ParticipantIp: 2130706433,
                    ParticipantPort: 2005,
                }
                err := objs.XdpIpTcMap.Put(uint32(4), &newUser) 
                if err != nil {
                    log.Fatal("Map Update: ", err)
                }
                shouldAdd = false
            }

            
        case <-stop:
            log.Print("Received signal, exiting..")
            return
        }
    }
}