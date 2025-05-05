# 🧠 Go WebRTC SFU Demo (with Mid-call Renegotiation)

This is a **minimal SFU (Selective Forwarding Unit)** written in Go using [Pion WebRTC](https://github.com/pion/webrtc). It demonstrates how to receive media tracks from peers, dynamically add them to other peers, and renegotiate mid-call — all using HTTP-based signaling.

---

## ✨ Features

- ✅ Forward video RTP packets to all connected peers
- ✅ Mid-call renegotiation (add tracks even after initial connection)
- ✅ Track buffering before negotiation is finalized
- ✅ Simple HTTP signaling using `/offer`, `/answer`, and `/renegotiate/:peer-id`
- ✅ Fake VP8 video generator for simulation

---

## 📁 Project Structure

```text
.
├── server.go     # SFU server handling forwarding and signaling
├── client.go     # Peer client sending and receiving video tracks
└── README.md     # This file
```

---

## 🛠️ Getting Started

### ✅ Requirements

- [Go 1.20+](https://golang.org/dl/)
- Internet access (for STUN)
- Two or more terminal windows (for multiple peers)

---

### 🔧 Install Dependencies

In the project folder, initialize the module and install Pion:

```bash
go mod init sfu-demo
go get github.com/pion/webrtc/v3
```

---

## 🚀 Running the Demo

### 1. Start the SFU server

```bash
go build
.\simple
```

The server starts at `http://localhost:8080`.

---

### 2. Start one or more clients in separate terminals

```bash
cd client
go build 
.\client
```

Each client will:
- Send a fake VP8 video stream
- Poll for new offers from the server
- Receive tracks from other clients as they're forwarded

---

## 🔍 Example Logs

### 🖥️ Server

```
[peer-123456] Received track: video
📡 Sending renegotiation offer to peer-987654
ICE state: connected
```

### 👤 Client

```
🔗 Connected as peer-123456
📡 Received renegotiation offer
✅ Sent renegotiation answer
🎥 Received track from SFU | Kind: video
📦 RTP packet received: 123 bytes
```

---

## 🧱 What You Can Build From Here

This project is a **starter template** for building real-world WebRTC backends:

- 🔁 Replace dummy video with actual webcam or GStreamer video
- 🔊 Add support for audio tracks
- 🌐 Use WebSockets for low-latency signaling
- 📊 Add Prometheus metrics for SFU monitoring
- 🌍 Support multiple rooms/sessions
- 💾 Record incoming streams to disk or S3
- 📺 Build a browser client (HTML + JS) to view the stream

---

## 🙌 Credits

This demo uses [Pion WebRTC](https://github.com/pion/webrtc), a fully native WebRTC implementation in Go.  
Thanks to the amazing open source contributors who make it possible to build WebRTC systems without a browser!

---

## 🤔 Questions? Feedback?

Want to extend this with:
- Real audio/video support?
- Custom signaling (e.g. over WebSockets)?
- TURN support for NAT traversal?

Feel free to open an issue, fork it, or message me — I'm happy to help!

---

Enjoy building with WebRTC! 💡🎥💬