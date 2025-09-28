package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

var (
	listenAddr         = flag.String("listen", "127.0.0.1:1080", "local SOCKS5 listen addr")
	wssServer          = flag.String("server", "wss://your.domain.com/ws", "WSS server URL (e.g. wss://host/ws)")
	sharedKey          = flag.String("key", "CHANGE_ME", "shared secret used as Sec-WebSocket-Protocol: 'tok <KEY>'")
	targetIP           = flag.String("target-ip", "192.168.69.85", "destination IP to tunnel")
	targetPort         = flag.String("target-port", "2096", "destination TCP port to tunnel")
	dialTimeout        = flag.Duration("dial-timeout", 10*time.Second, "timeout for direct TCP dials")
	insecureSkipVerify = flag.Bool("insecure-skip-verify", false, "skip TLS verification for WSS (testing only)")
)

func main() {
	flag.Parse()

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *listenAddr, err)
	}
	log.Printf("SOCKS5 listening on %s | Tunnel only %s:%s via %s",
		*listenAddr, *targetIP, *targetPort, *wssServer)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleSOCKS(c)
	}
}

// -------------------- SOCKS5 --------------------

func handleSOCKS(cli net.Conn) {
	defer cli.Close()
	_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
	verNM := make([]byte, 2)
	if _, err := io.ReadFull(cli, verNM); err != nil {
		log.Printf("greet hdr: %v", err)
		return
	}
	if verNM[0] != 0x05 {
		log.Printf("bad VER: %d", verNM[0])
		return
	}
	nMethods := int(verNM[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(cli, methods); err != nil {
		log.Printf("greet methods: %v", err)
		return
	}
	if _, err := cli.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(cli, reqHdr); err != nil {
		log.Printf("req hdr: %v", err)
		return
	}
	ver, cmd, atyp := reqHdr[0], reqHdr[1], reqHdr[3]
	if ver != 0x05 || cmd != 0x01 {
		_ = writeSocksReply(cli, 0x07, "0.0.0.0:0")
		return
	}

	var destHost string
	switch atyp {
	case 0x01:
		b := make([]byte, 6)
		if _, err := io.ReadFull(cli, b); err != nil {
			log.Printf("read ipv4 addr: %v", err)
			return
		}
		ip := net.IP(b[0:4]).String()
		port := int(b[4])<<8 | int(b[5])
		destHost = net.JoinHostPort(ip, strconv.Itoa(port))
	case 0x03:
		var lb [1]byte
		if _, err := io.ReadFull(cli, lb[:]); err != nil {
			log.Printf("read domain len: %v", err)
			return
		}
		dlen := int(lb[0])
		b := make([]byte, dlen+2)
		if _, err := io.ReadFull(cli, b); err != nil {
			log.Printf("read domain: %v", err)
			return
		}
		host := string(b[:dlen])
		port := int(b[dlen])<<8 | int(b[dlen+1])
		destHost = net.JoinHostPort(host, strconv.Itoa(port))
	case 0x04:
		b := make([]byte, 18)
		if _, err := io.ReadFull(cli, b); err != nil {
			log.Printf("read ipv6 addr: %v", err)
			return
		}
		ip := net.IP(b[0:16]).String()
		port := int(b[16])<<8 | int(b[17])
		destHost = net.JoinHostPort(ip, strconv.Itoa(port))
	default:
		log.Printf("unknown ATYP: %d", atyp)
		_ = writeSocksReply(cli, 0x08, "0.0.0.0:0")
		return
	}
	_ = cli.SetDeadline(time.Time{})

	host, portStr, _ := net.SplitHostPort(destHost)
	destIP := host
	if net.ParseIP(host) == nil {
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			destIP = ips[0].String()
		}
	}

	if destIP == *targetIP && portStr == *targetPort {
		if err := handleViaWSS(cli, destHost); err != nil {
			log.Printf("via WSS %s: %v", destHost, err)
			_ = writeSocksReply(cli, 0x05, "0.0.0.0:0")
		}
		return
	}

	// DIRECT
	rc, err := net.DialTimeout("tcp", destHost, *dialTimeout)
	if err != nil {
		log.Printf("direct dial %s: %v", destHost, err)
		_ = writeSocksReply(cli, 0x05, "0.0.0.0:0")
		return
	}
	defer rc.Close()

	if err := writeSocksReply(cli, 0x00, "0.0.0.0:0"); err != nil {
		return
	}

	pipeBoth(rc, cli)
}

func writeSocksReply(conn net.Conn, rep byte, _bind string) error {
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

func pipeBoth(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// -------------------- WSS tunnel --------------------

func handleViaWSS(cli net.Conn, destHost string) error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: *insecureSkipVerify,
	}
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 20 * time.Second,
		TLSClientConfig:  tlsConf,
		Subprotocols:     []string{"tok " + *sharedKey},
	}

	ws, resp, err := dialer.Dial(*wssServer, nil)
	if err != nil {
		if resp != nil {
			log.Printf("wss status: %s", resp.Status)
		}
		return fmt.Errorf("wss dial: %w", err)
	}

	closed := make(chan struct{})
	defer func() {
		select {
		case <-closed:
		default:
			_ = ws.Close()
		}
	}()

	// 2) initial frame: [1 byte len][host:port]
	if len(destHost) > 255 {
		return fmt.Errorf("target too long")
	}
	init := append([]byte{byte(len(destHost))}, []byte(destHost)...)
	if err := ws.WriteMessage(websocket.BinaryMessage, init); err != nil {
		return fmt.Errorf("write init: %w", err)
	}

	// 3) reply success to SOCKS client
	if err := writeSocksReply(cli, 0x00, "0.0.0.0:0"); err != nil {
		return err
	}

	errCh := make(chan error, 2)

	// WS -> CLI (downstream)
	go func() {
		defer func() { errCh <- io.EOF }()
		for {
			mt, data, rerr := ws.ReadMessage()
			if rerr != nil {
				errCh <- rerr
				return
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			if len(data) > 0 {
				if _, werr := cli.Write(data); werr != nil {
					errCh <- werr
					return
				}
			}
		}
	}()

	// CLI -> WS (upstream)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, rerr := cli.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}
			if rerr != nil {
				errCh <- rerr
				return
			}
		}
	}()

	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(3*time.Second))
			case <-closed:
				return
			}
		}
	}()

	e := <-errCh
	close(closed)
	_ = ws.Close()
	return e
}
