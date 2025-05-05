package main

import (
	"encoding/json"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"math/rand"
	"net/http"
	"sync"
	"time"
	"math/bits"
	"github.com/cilium/ebpf"
	"github.com/pion/webrtc/v3"
)

type sfuIpRecord struct {
	ParticipantIp   uint32
	ParticipantPort uint16
	_               [2]byte
}

type Peer struct {
	ID               string
	PC               *webrtc.PeerConnection
	OutTracks        map[string]*webrtc.TrackLocalStaticRTP
	InTracks         map[string]*webrtc.TrackRemote
	OfferChan        chan webrtc.SessionDescription
	RemoteAnswerChan chan webrtc.SessionDescription
	mu               sync.Mutex
}

type IndexAllocator struct {
    availableIndices []uint32          
    peerToIndex      map[string]uint32 
}

type SFUServer struct {
    allocator *IndexAllocator
    ipMap     *ebpf.Map
	isEBPF	bool
}

func NewIndexAllocator(maxIndices uint32) *IndexAllocator {
    indices := make([]uint32, maxIndices)
    for i := uint32(0); i < maxIndices; i++ {
        indices[i] = i
    }
    return &IndexAllocator{
        availableIndices: indices,
        peerToIndex:      make(map[string]uint32),
    }
}

// Assign an index to a peerID
func (a *IndexAllocator) Assign(peerID string) (uint32, bool) {
    if idx, exists := a.peerToIndex[peerID]; exists {
        return idx, true // Already assigned
    }
    if len(a.availableIndices) == 0 {
        return 0, false // No available indices
    }
    idx := a.availableIndices[0]
    a.availableIndices = a.availableIndices[1:] // Pop front
    a.peerToIndex[peerID] = idx
    return idx, true
}

// Release the index when peer disconnects
func (a *IndexAllocator) Release(peerID string) {
    if idx, exists := a.peerToIndex[peerID]; exists {
        delete(a.peerToIndex, peerID)
        a.availableIndices = append(a.availableIndices, idx) // Push back
    }
}

var peers sync.Map

func IntToIP(ip uint32) net.IP {
	result := make(net.IP, 4)
	result[0] = byte(ip)
	result[1] = byte(ip >> 8)
	result[2] = byte(ip >> 16)
	result[3] = byte(ip >> 24)
	return result
}

func ipToUint32(ipStr string) uint32 {
    ip := net.ParseIP(ipStr).To4()
    return binary.BigEndian.Uint32(ip)
}

// Convert port to network byte order (big endian)
func htons(port uint16) uint16 {
    return (port<<8)&0xff00 | port>>8
}

func generatePeerID() string {
	return fmt.Sprintf("peer-%d", rand.Intn(1000000))
}

func (s *SFUServer) newPeerConnection() (*webrtc.PeerConnection, error) {
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
	}
	return webrtc.NewPeerConnection(config)
}

func (s *SFUServer) offerHandler(w http.ResponseWriter, r *http.Request) {
	peerID := generatePeerID()
	pc, err := s.newPeerConnection()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	peer := &Peer{
		ID:               peerID,
		PC:               pc,
		OutTracks:        make(map[string]*webrtc.TrackLocalStaticRTP),
		InTracks:         make(map[string]*webrtc.TrackRemote),
		OfferChan:        make(chan webrtc.SessionDescription, 1),
		RemoteAnswerChan: make(chan webrtc.SessionDescription, 1),
	}

	peers.Store(peerID, peer)

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		log.Printf("[%s] ICE state: %s", peerID, state.String())
		if state == webrtc.ICEConnectionStateConnected {
			candidatePair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
			if err != nil || candidatePair == nil {
				log.Printf("[%s] No selected ICE candidate pair yet: %v", peerID, err)
				return
			}

			remoteIP := candidatePair.Remote.Address
			remotePort := uint16(candidatePair.Remote.Port)
			log.Printf("Peer %s connected from %s:%d", peerID, remoteIP, remotePort)
		}
		if s.isEBPF {
			switch state {
			case webrtc.ICEConnectionStateConnected:
				idx, ok := s.allocator.Assign(peerID)
				if !ok {
					log.Printf("[%s] No available indices in eBPF map!", peerID)
					return
				}
		
				// Extract remote IP and port from the selected ICE candidate
				candidatePair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
				if err != nil || candidatePair == nil {
					log.Printf("[%s] No selected ICE candidate pair yet: %v", peerID, err)
					return
				}
		
				remoteIP := candidatePair.Remote.Address
				remotePort := uint16(candidatePair.Remote.Port)
				log.Printf("Peer %s connected from %s:%d", peerID, remoteIP, remotePort)
				entry := sfuIpRecord{
					ParticipantIp:   ipToUint32(remoteIP),
					ParticipantPort: htons(remotePort),
				}
		
				if s.ipMap != nil {
					if err := s.ipMap.Put(idx, &entry);err != nil {
						log.Printf("[%s] Failed to update eBPF map: %v", peerID, err)
					} else {
						log.Printf("[%s] Added to eBPF map at index %d", peerID, idx)
					}
				}
		
			case webrtc.ICEConnectionStateDisconnected:
		
				idx, exists := s.allocator.peerToIndex[peerID]
				if !exists {
					log.Printf("[%s] No index assigned, skipping delete", peerID)
					return
				}
				
				if err := s.ipMap.Put(idx, &sfuIpRecord{});err != nil {
					log.Printf("[%s] Failed to delete from eBPF map: %v", peerID, err)
				} else {
					log.Printf("[%s] Removed from eBPF map at index %d", peerID, idx)
				}
				s.allocator.Release(peerID)
			}
		}

	})
	log.Print("Got Track from peer", peer.OutTracks)

	// pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
	//     log.Printf("[%s] Received track: %s", peerID, track.Kind().String())
	//     time.Sleep(200 * time.Millisecond)
	//     go forwardTrackToPeers(peerID, track)
	// })
	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		kind := track.Kind().String()
		log.Printf("[%s] Received track: %s", peerID, kind)

		peer.mu.Lock()
		peer.InTracks[kind] = track
		peer.mu.Unlock()

		// Start reading RTP packets from this track
		go func() {
			buf := make([]byte, 1500)
			for {
				n, _, err := track.Read(buf)
				if err != nil {
					log.Printf("[%s] RTP read error: %v", peerID, err)
					return
				}

				// Forward to all other peers from InTracks
				peers.Range(func(_, val any) bool {
					other := val.(*Peer)
					if other.ID == peerID {
						return true // skip sender
					}

					other.mu.Lock()
					defer other.mu.Unlock()

					outTrack := other.OutTracks[kind]
					if outTrack == nil {
						// Create and attach outbound track
						newTrack, err := webrtc.NewTrackLocalStaticRTP(track.Codec().RTPCodecCapability, track.ID(), track.StreamID())
						if err != nil {
							log.Printf("❌ Couldn't create outbound track: %v", err)
							return true
						}

						sender, err := other.PC.AddTrack(newTrack)
						if err != nil {
							log.Printf("❌ Couldn't add track to peer %s: %v", other.ID, err)
							return true
						}

						go func() {
							rtcpBuf := make([]byte, 1500)
							for {
								if _, _, err := sender.Read(rtcpBuf); err != nil {
									return
								}
							}
						}()

						other.OutTracks[kind] = newTrack

						// Trigger renegotiation
						offer, err := other.PC.CreateOffer(nil)
						if err == nil && other.PC.SetLocalDescription(offer) == nil {
							if desc := other.PC.LocalDescription(); desc != nil {
								select {
								case other.OfferChan <- *desc:
									log.Printf("📡 Sent renegotiation offer to %s", other.ID)
								default:
									log.Printf("⚠️ OfferChan full for %s", other.ID)
								}
							}
						}
					}

					// Write RTP packet
					if other.OutTracks[kind] != nil {
						//log.Printf("Sending track from %s to %s", peerID, other.ID)
						_, err := other.OutTracks[kind].Write(buf[:n])
						if err != nil {
							log.Printf("⚠️ RTP forward error to %s: %v", other.ID, err)
						}
					}

					return true
				})
			}
		}()
	})

	var offer webrtc.SessionDescription
	if err := json.NewDecoder(r.Body).Decode(&offer); err != nil {
		http.Error(w, "Invalid SDP", http.StatusBadRequest)
		return
	}

	if err := pc.SetRemoteDescription(offer); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := pc.SetLocalDescription(answer); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(struct {
		SDP    webrtc.SessionDescription `json:"sdp"`
		PeerID string                    `json:"peer_id"`
	}{*pc.LocalDescription(), peerID})
}

func forwardTrackToPeers(fromPeerID string, track *webrtc.TrackRemote) {
	buf := make([]byte, 1500)
	for {

		n, _, err := track.Read(buf)
		if err != nil {
			log.Printf("[%s] Error reading track: %v", fromPeerID, err)
			return
		}

		peers.Range(func(key, value any) bool {
			peer := value.(*Peer)
			if peer.ID == fromPeerID {
				return true
			}

			peer.mu.Lock()
			log.Print("KIND OF TRACK: " + track.Kind().String())
			localTrack, ok := peer.OutTracks[track.Kind().String()]
			log.Print("Tracks ", localTrack)

			if !ok {

				newTrack, err := webrtc.NewTrackLocalStaticRTP(
					track.Codec().RTPCodecCapability, track.ID(), track.StreamID())
				if err != nil {
					log.Printf("Error creating local track: %v", err)
					peer.mu.Unlock()
					return true
				}

				sender, err := peer.PC.AddTrack(newTrack)
				if err != nil {
					log.Printf("Error adding track to peer %s: %v", peer.ID, err)
					peer.mu.Unlock()
					return true
				}

				go func() {
					rtcpBuf := make([]byte, 1500)
					for {
						if _, _, rtcpErr := sender.Read(rtcpBuf); rtcpErr != nil {
							return
						}
					}
				}()

				peer.OutTracks[track.Kind().String()] = newTrack
				localTrack = newTrack

				offer, err := peer.PC.CreateOffer(nil)
				if err == nil {
					peer.PC.SetLocalDescription(offer)
					peer.OfferChan <- *peer.PC.LocalDescription()
				}
			}

			if localTrack != nil {
				_, err := localTrack.Write(buf[:n])
				if err != nil {
					log.Printf("Error forwarding packet: %v", err)
				}
			}

			peer.mu.Unlock()
			return true
		})
	}
}

func (s *SFUServer) renegotiateHandler(w http.ResponseWriter, r *http.Request) {
	peerID := r.URL.Path[len("/renegotiate/"):]
	if val, ok := peers.Load(peerID); ok {
		peer := val.(*Peer)
		select {
		case offer := <-peer.OfferChan:
			json.NewEncoder(w).Encode(offer)
		case <-time.After(2 * time.Second):
			w.WriteHeader(http.StatusNoContent)
		}
	} else {
		http.Error(w, "Peer not found", http.StatusNotFound)
	}
}

func (s *SFUServer) answerHandler(w http.ResponseWriter, r *http.Request) {
	peerID := r.URL.Path[len("/answer/"):]
	if val, ok := peers.Load(peerID); ok {
		peer := val.(*Peer)

		var answer webrtc.SessionDescription
		if err := json.NewDecoder(r.Body).Decode(&answer); err != nil {
			http.Error(w, "Invalid SDP", http.StatusBadRequest)
			return
		}

		if err := peer.PC.SetRemoteDescription(answer); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	} else {
		http.Error(w, "Peer not found", http.StatusNotFound)
	}
}

func setupEBPF() (*ebpf.Map, error){
	ipMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xdp_ip_tc_map", nil)
	if err != nil {
		log.Fatalf("❌ Failed to load pinned eBPF map: %v", err)
		return nil, err
	}
	log.Println("✅ Loaded eBPF map from /sys/fs/bpf/xdp_ip_tc_map")
	var participant sfuIpRecord
	ipMap.Lookup(uint32(0), &participant)
	ip := IntToIP(bits.ReverseBytes32(participant.ParticipantIp)).String()
	port := bits.ReverseBytes16(participant.ParticipantPort)
	log.Printf("Curent Participant IP %s, Current Participant Port %d", ip, port)
	return ipMap, nil
}

func main() {
	useEbpf := flag.Bool("ebpf", false, "Enable eBPF functionality")
	flag.Parse()

	server := &SFUServer{
        allocator: NewIndexAllocator(10),
    }

	// Log the flag value
	log.Printf("eBPF Enabled: %v", *useEbpf)
	if *useEbpf {
		ipMap, err := setupEBPF()
		if err != nil {
			log.Fatalf("eBPF setup failed: %v", err)
		}
		server.ipMap = ipMap
		server.isEBPF = true
	} else {
		log.Println("Skipping eBPF setup...")
		server.isEBPF = false
	}
	rand.Seed(time.Now().UnixNano())

	http.HandleFunc("/offer", server.offerHandler)
	http.HandleFunc("/renegotiate/", server.renegotiateHandler)
	http.HandleFunc("/answer/", server.answerHandler)

	log.Println("✅ SFU Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
