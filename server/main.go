package main

import (
	"bufio"
	"errors"
	"flag"
	"log"
	"net"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/fasthttp/websocket"
	"github.com/valyala/fasthttp"
)

var (
	listenAddr = flag.String("listen", "127.0.0.1:8080", "WS listen addr (behind TLS reverse proxy)")
	sharedKey  = flag.String("key", "CHANGE_ME", "shared secret for Sec-WebSocket-Protocol (format: tok <key>)")
	wsPath     = flag.String("path", "/ws", "WebSocket path")
	dialTO     = flag.Duration("dial-timeout", 7*time.Second, "TCP dial timeout to targets")
	ioTO       = flag.Duration("io-timeout", 90*time.Second, "I/O idle timeout (extended on activity)")
	pingEvery  = flag.Duration("ping-every", 20*time.Second, "WebSocket ping interval")
)

var upgrader = websocket.FastHTTPUpgrader{
	CheckOrigin:       func(ctx *fasthttp.RequestCtx) bool { return true },
	ReadBufferSize:    64 * 1024,
	WriteBufferSize:   64 * 1024,
	EnableCompression: false,
}

func main() {
	flag.Parse()

	r := router.New()
	r.GET(*wsPath, wsHandler)

	s := &fasthttp.Server{
		Handler:            r.Handler,
		Name:               "wstun",
		ReadBufferSize:     64 * 1024,
		WriteBufferSize:    64 * 1024,
		DisableKeepalive:   false,
		MaxRequestsPerConn: 0,
	}
	log.Printf("listening on %s, ws path %s", *listenAddr, *wsPath)
	if err := s.ListenAndServe(*listenAddr); err != nil {
		log.Fatal(err)
	}
}

func wsHandler(ctx *fasthttp.RequestCtx) {
	if !checkProtoToken(ctx, "tok "+*sharedKey) {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		return
	}

	if err := upgrader.Upgrade(ctx, func(conn *websocket.Conn) {
		resetRWDeadlines := func() {
			_ = conn.SetReadDeadline(time.Now().Add(*ioTO))
			_ = conn.SetWriteDeadline(time.Now().Add(*ioTO))
		}
		resetRWDeadlines()

		conn.SetPongHandler(func(_ string) error {
			_ = conn.SetReadDeadline(time.Now().Add(*ioTO))
			return nil
		})
		conn.SetCloseHandler(func(code int, text string) error {
			log.Printf("ws close: %d %s", code, text)
			return nil
		})

		mt, first, err := conn.ReadMessage()
		if err != nil {
			log.Printf("read init: %v", err)
			_ = conn.Close()
			return
		}
		if mt != websocket.BinaryMessage || len(first) < 2 {
			_ = conn.Close()
			return
		}
		n := int(first[0])
		if 1+n > len(first) {
			_ = conn.Close()
			return
		}
		target := string(first[1 : 1+n])
		if !validTarget(target) {
			log.Printf("invalid target: %q", target)
			_ = conn.Close()
			return
		}

		dialer := net.Dialer{Timeout: *dialTO}
		dst, err := dialer.Dial("tcp", target)
		if err != nil {
			log.Printf("dial %s: %v", target, err)
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "dial failed"),
				time.Now().Add(2*time.Second))
			_ = conn.Close()
			return
		}
		defer dst.Close()

		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		_ = dst.SetDeadline(time.Now().Add(*ioTO))

		errCh := make(chan error, 2)

		// WS -> TCP
		go func() {
			for {
				_ = conn.SetReadDeadline(time.Now().Add(*ioTO))
				mt, data, err := conn.ReadMessage()
				if err != nil {
					errCh <- err
					return
				}
				if mt != websocket.BinaryMessage {
					continue
				}
				if len(data) > 0 {
					if _, err := dst.Write(data); err != nil {
						errCh <- err
						return
					}
					_ = dst.SetDeadline(time.Now().Add(*ioTO))
				}
			}
		}()

		// TCP -> WS
		go func() {
			br := bufio.NewReaderSize(dst, 64*1024)
			buf := make([]byte, 64*1024)
			for {
				_ = dst.SetReadDeadline(time.Now().Add(*ioTO))
				n, err := br.Read(buf)
				if n > 0 {
					_ = conn.SetWriteDeadline(time.Now().Add(*ioTO))
					if werr := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
						errCh <- werr
						return
					}
					resetRWDeadlines()
				}
				if err != nil {
					errCh <- err
					return
				}
			}
		}()

		// Ping keepalive
		ping := time.NewTicker(*pingEvery)
		defer ping.Stop()

		for {
			select {
			case err := <-errCh:
				if err != nil && !errors.Is(err, net.ErrClosed) {
					log.Printf("pipe error: %v", err)
				}
				_ = conn.Close()
				return
			case <-ping.C:
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(3*time.Second)); err != nil {
					log.Printf("ping err: %v", err)
					_ = conn.Close()
					return
				}
			}
		}
	}); err != nil {
		log.Printf("upgrade: %v", err)
	}
}

func checkProtoToken(ctx *fasthttp.RequestCtx, want string) bool {
	h := string(ctx.Request.Header.Peek("Sec-WebSocket-Protocol"))
	if h == "" {
		return false
	}
	for _, p := range strings.Split(h, ",") {
		if strings.TrimSpace(p) == want {
			ctx.Response.Header.Set("Sec-WebSocket-Protocol", want)
			return true
		}
	}
	return false
}

func validTarget(s string) bool {
	if !strings.Contains(s, ":") || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	return true
}
