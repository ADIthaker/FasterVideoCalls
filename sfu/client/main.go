// package main

// import (
// 	"bytes"
// 	"encoding/json"
// 	"fmt"
// 	"io/ioutil"
// 	"log"
// 	"net/http"
// 	"time"
// 	"github.com/pion/rtp"
// 	"github.com/pion/webrtc/v3"
// )

// func sendFakeVideo(pc *webrtc.PeerConnection) (*webrtc.SessionDescription, error) {
// 	// 1. Create a video track using VP8
// 	videoTrack, err := webrtc.NewTrackLocalStaticRTP(
// 		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
// 		"video", "pion-client",
// 	)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// 2. Add the track BEFORE creating the offer
// 	_, err = pc.AddTrack(videoTrack)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// 3. Start sending fake RTP packets (~30fps)
// 	go func() {
// 		log.Println("📡 Starting fake video stream...")
// 		ticker := time.NewTicker(33 * time.Millisecond)
// 		defer ticker.Stop()

// 		var seq uint16 = 0
// 		var timestamp uint32 = 0
// 		for range ticker.C {
// 			packet := &rtp.Packet{
// 				Header: rtp.Header{
// 					Version:        2,
// 					PayloadType:    96, // VP8
// 					SequenceNumber: seq,
// 					Timestamp:      timestamp,
// 					SSRC:           12345678,
// 				},
// 				Payload: []byte{0x00}, // Dummy frame data
// 			}

// 			err := videoTrack.WriteRTP(packet)
// 			if err != nil {
// 				log.Printf("Error writing RTP packet: %v", err)
// 				return
// 			}

// 			seq++
// 			timestamp += 3000 // ~1 frame @ 90kHz clock for 30fps
// 		}
// 	}()

// 	// 4. Create the offer
// 	offer, err := pc.CreateOffer(nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// 5. Set local description
// 	if err := pc.SetLocalDescription(offer); err != nil {
// 		return nil, err
// 	}

// 	// 6. Wait for ICE candidates
// 	<-webrtc.GatheringCompletePromise(pc)

// 	// 7. Return the full offer (with candidates)
// 	return pc.LocalDescription(), nil
// }

// func main() {
// 	config := webrtc.Configuration{
// 		ICEServers: []webrtc.ICEServer{
// 			{
// 				URLs: []string{"stun:stun.l.google.com:19302"},
// 			},
// 		},
// 	}

// 	pc, err := webrtc.NewPeerConnection(config)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
// 		log.Printf("🎥 Received forwarded track from server | Kind: %s | Codec: %s",
// 			track.Kind(), track.Codec().MimeType)
	
// 		go func() {
// 			buf := make([]byte, 1500)
// 			for {
// 				n, _, err := track.Read(buf)
// 				if err != nil {
// 					log.Printf("Error reading incoming RTP: %v", err)
// 					return
// 				}
// 				log.Printf("Received RTP packet from server: %d bytes", n)
// 			}
// 		}()
// 	})

// 	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
// 		if c != nil {
// 			log.Printf("ICE candidate gathered: %s:%d", c.Address, c.Port)
// 		} else {
// 			log.Println("ICE gathering complete")
// 		}
// 	})

// 	// Optional: Create a data channel
// 	_, err = pc.CreateDataChannel("data", nil)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	// Create offer
// 	offer, err := sendFakeVideo(pc)
// 	if err != nil {
// 		log.Fatalf("sendFakeVideo failed: %v", err)
// 	}


// 	log.Println("Gathering complete — sending offer to server")

// 	// Send the offer to the server
// 	offerJSON, err := json.Marshal(offer)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	resp, err := http.Post("http://localhost:8080/offer", "application/json", bytes.NewReader(offerJSON))
// 	if err != nil {
// 		log.Fatal("Error sending offer:", err)
// 	}
// 	defer resp.Body.Close()

// 	answerBytes, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	var answer webrtc.SessionDescription
// 	if err := json.Unmarshal(answerBytes, &answer); err != nil {
// 		log.Fatal(err)
// 	}

// 	err = pc.SetRemoteDescription(answer)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Println("🎉 Connected! Waiting for events...")
// 	sendFakeVideo(pc)
// 	select {}
// }
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "math/rand"
    "flag"
    "net/http"
    "time"

    "github.com/pion/rtp"
    "github.com/pion/webrtc/v3"
)

func sendFakeVideo(track *webrtc.TrackLocalStaticRTP) {
    go func() {
        ticker := time.NewTicker(33 * time.Millisecond)
        defer ticker.Stop()
        var seq uint16
        var timestamp uint32
        for range ticker.C {
            pkt := &rtp.Packet{
                Header: rtp.Header{
                    Version:        2,
                    PayloadType:    96,
                    SequenceNumber: seq,
                    Timestamp:      timestamp,
                    SSRC:           12345678,
                },
                Payload: []byte{0x00},
            }
            err := track.WriteRTP(pkt)
            if err != nil {
                log.Printf("❌ Error writing RTP: %v", err)
                return
            }
            seq++
            timestamp += 3000
        }
    }()
}

func main() {
    duration := flag.Int("duration", 30, "How long to stay connected before exiting (in seconds)")
    flag.Parse()
    rand.Seed(time.Now().UnixNano())
    config := webrtc.Configuration{
        ICEServers: []webrtc.ICEServer{
            {URLs: []string{"stun:stun.l.google.com:19302"}},
        },
    }

    pc, err := webrtc.NewPeerConnection(config)
    if err != nil {
        log.Fatal(err)
    }

    pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
        log.Printf("Received track from SFU | Kind: %s", track.Kind())
        go func() {
            buf := make([]byte, 1500)
            firstRTP := true
            firstRTPStart := time.Now()
    
            var packetCount int
            var byteCount int
    
            go func() {
                ticker := time.NewTicker(1 * time.Second)
                lastPackets := 0
                lastBytes := 0
                for range ticker.C {
                    pps := packetCount - lastPackets
                    bps := byteCount - lastBytes
                    lastPackets = packetCount
                    lastBytes = byteCount
    
                    log.Printf("📈 Packets: %d/s | Bitrate: %.2f kbps", pps, float64(bps*8)/1000.0)
                }
            }()
    
            for {
                n, _, err := track.Read(buf)
                if err != nil {
                    log.Printf("❌ RTP read error: %v", err)
                    return
                }
    
                if firstRTP {
                    log.Printf("📦 Time to First RTP: %.2fms", time.Since(firstRTPStart).Seconds()*1000)
                    firstRTP = false
                }
    
                packetCount++
                byteCount += n
            }
        }()
        buf := make([]byte, 1500)
        for {
            n, _, err := track.Read(buf)
            if err != nil {
                log.Printf("Track read error: %v", err)
                return
            }
            log.Printf("RTP packet received: %d bytes", n)
        }
    })

    videoTrack, err := webrtc.NewTrackLocalStaticRTP(
        webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8}, "video", "pion-client")
    if err != nil {
        log.Fatal(err)
    }
    _, err = pc.AddTrack(videoTrack)
    if err != nil {
        log.Fatal(err)
    }

    sendFakeVideo(videoTrack)

    offer, err := pc.CreateOffer(nil)
    if err != nil {
        log.Fatal(err)
    }
    if err := pc.SetLocalDescription(offer); err != nil {
        log.Fatal(err)
    }

    <-webrtc.GatheringCompletePromise(pc)

    offerBuf, _ := json.Marshal(pc.LocalDescription())
    resp, err := http.Post("http://localhost:8080/offer", "application/json", bytes.NewReader(offerBuf))
    if err != nil {
        log.Fatalf("Failed to send offer: %v", err)
    }

    var respData struct {
        SDP    webrtc.SessionDescription `json:"sdp"`
        PeerID string                    `json:"peer_id"`
    }
    body, _ := ioutil.ReadAll(resp.Body)
    json.Unmarshal(body, &respData)

    err = pc.SetRemoteDescription(respData.SDP)
    if err != nil {
        log.Fatalf("Failed to set remote description: %v", err)
    }

    peerID := respData.PeerID
    log.Printf("Connected as %s", peerID)

    go func() {
        for {
            time.Sleep(1 * time.Second)
            renegotiateURL := fmt.Sprintf("http://localhost:8080/renegotiate/%s", peerID)
            res, err := http.Get(renegotiateURL)
            if err != nil || res.StatusCode != 200 {
                continue
            }

            var offer webrtc.SessionDescription
            json.NewDecoder(res.Body).Decode(&offer)
            log.Println("📡 Received renegotiation offer")

            if err := pc.SetRemoteDescription(offer); err != nil {
                log.Printf("Failed to set remote SDP: %v", err)
                continue
            }

            answer, err := pc.CreateAnswer(nil)
            if err != nil {
                log.Printf("Failed to create answer: %v", err)
                continue
            }
            pc.SetLocalDescription(answer)

            answerBuf, _ := json.Marshal(answer)
            http.Post(fmt.Sprintf("http://localhost:8080/answer/%s", peerID), "application/json", bytes.NewReader(answerBuf))
            log.Println("Sent renegotiation answer")
        }
    }()

    log.Printf("🕒 Client will exit after %d seconds\n", *duration)
    time.Sleep(time.Duration(*duration) * time.Second)
    log.Println("👋 Client exiting after duration.")
}
