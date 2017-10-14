// Use of this source code is governed by a
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/context"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/luSunn/rserver/util"
)

var PROGRAM = ""

var VERSION = "0.0.1"

const (
	// address types
	IPv4   uint8 = 1
	DOMAIN uint8 = 3
	IPv6   uint8 = 4
)

const (
	// socks status
	GRANTED uint8 = iota
	GENERALFAILURE
	NOTALLOWED
	NETWORKUNREACHABLE
	HOSTUNREACHABLE
	CONNECTIONREFUSED
	TTLEXPIRED
	COMMANDNOTSUPPORTED
	ADDRESSNOTSUPPORTED
)

const (
	_ uint8 = iota
	// command code
	CONNECTCMD
	BINDCOMD
	UDPASSOCIATECMD
)

const TCP_BUFFER = 32 * 1024

const UDP_BUFFER = 2 ^ 16

var ctxb = context.Background()

type key int

const reqIDKey key = 0

type RequestID string

func newID() RequestID {
	bytes := make([]byte, 16) // 128 bits long id
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("rand.Rand: %v", err))
	}
	return RequestID(hex.EncodeToString(bytes))
}

func newContext(ctx context.Context, reqID RequestID) context.Context {
	return context.WithValue(ctx, reqIDKey, reqID)
}

func fromContext(ctx context.Context) (RequestID, bool) {
	reqID, ok := ctx.Value(reqIDKey).(RequestID)
	return reqID, ok
}

func loggingInfo(c context.Context, msg string, i ...interface{}) {
	var line bytes.Buffer
	line.WriteString("\033[0;32m")
	line.WriteString(time.Now().UTC().Format("[2006-01-02T15:04:05.999] "))
	line.WriteString("\033[0m")
	if reqID, ok := fromContext(c); ok {
		fmt.Fprintf(&line, "\033[1;35m")
		fmt.Fprintf(&line, "[%s] ", reqID)
	}
	fmt.Fprintf(&line, "\033[1;37m")
	fmt.Fprintf(&line, msg, i...)
	fmt.Println(line.String())
	fmt.Fprintf(&line, "\033[0m")
}

type socket struct {
	ip       net.IP
	port     int
	addrType uint8
	domain   []byte
	reqbuf   io.Reader
	network  string
	ctx      context.Context
}

func (s *socket) dial() (net.Conn, error) {
	return net.Dial(s.network, s.String())
}

func (s *socket) String() string {
	return net.JoinHostPort(s.ip.String(), strconv.Itoa(s.port))
}

// Usage prints out the uesage of this app.
var Usage = func() {
	text := `rserver- network realy server in Go
Usage:
rserver rserver [-c -a 127.0.0.1 -p 1080 -s 0000:1a04::ff3c:23bv:fe92:fff ] [-r -a 0000:1a04::ff3c:23bv:fe92:fff -p 5000]

`
	fmt.Fprintf(os.Stderr, text)
	flag.PrintDefaults()
}

type args struct {
	isServer     bool
	isClient     bool
	remoteServer string
	serverAddr   string
	serverPort   int
	method       string
	password     string
	config       string // path to config file
}

func parseArgs() args {
	var a args

	// parse flags
	flag.BoolVar(&a.isClient, "c", false, "run as `client`")
	flag.BoolVar(&a.isServer, "r", false, "run as `server`")
	flag.StringVar(&a.remoteServer, "s", "", "remote server address is required when running as client.")
	flag.StringVar(&a.serverAddr, "a", "127.0.0.1", "server address")
	flag.IntVar(&a.serverPort, "p", 1080, "server port")
	flag.StringVar(&a.method, "m", "aes-256-cfb", "encryption method")
	flag.StringVar(&a.config, "C", "./config.json", "path to config file")
	flag.StringVar(&a.password, "P", "I-am-having-an-existential-crisis", "password to authorise clients")

	flag.Usage = Usage
	flag.Parse()

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}
	return a
}

func main() {
	ctx := context.Background()
	args := parseArgs()

	conf := &util.Config{}

	// load Crypto along with password and method
	crypt := &util.Crypto{
		Password: args.password,
		Method:   args.method,
	}

	conf.Encryption = crypt

	conf.ServerPort = args.serverPort
	conf.ServerAddr = args.serverAddr

	if args.isClient {
		if args.remoteServer == "" {
			fmt.Fprintf(os.Stderr, "remote server address is required when running as client.\n\n")
			flag.Usage()
			os.Exit(1)
		}
		loggingInfo(ctx, "server is up and running in client mode  port:%d", args.serverPort)
		conf.IsClient = true
		conf.Servers = append(conf.Servers, args.remoteServer)

	} else if args.isServer {
		loggingInfo(ctx, "server is up and running in server mode  port:%d", args.serverPort)
		conf.IsServer = true
	}

	eventLoop(conf)
}

// eventLoop launches udp and tcp relay goroutines to listen to both of them.
func eventLoop(conf *util.Config) error {

	errCh := make(chan error)

	go udpRelay(errCh, conf)
	go tcpRelay(errCh, conf)

	for {
		e := <-errCh
		if e != nil {
			return e
		}
	}
}

func udpRelay(errCh chan error, conf *util.Config) error {
	ctx := context.Background()

	var err error
	var udpadr *net.UDPAddr

	port := conf.ServerPort
	addr := fmt.Sprintf("%s:%d", conf.ServerAddr, port)
	if conf.IsClient {
		udpadr, err = net.ResolveUDPAddr("udp", addr)
	} else {
		udpadr, err = net.ResolveUDPAddr("udp", addr)
	}

	if err != nil {
		loggingInfo(ctx, "ERROR udpRelay: %v", err)
		return err
	}

	ln, err := net.ListenUDP("udp", udpadr)
	if err != nil {
		panic(err)
	}

	defer ln.Close()

	rb := make([]byte, 10)

	for {
		n, addr, err := ln.ReadFromUDP(rb)
		errCh <- err
		ctx := newContext(context.Background(), newID())
		loggingInfo(ctx, "udp request: addr=%v data=%v", addr, rb[:n])
	}
}

func tcpRelay(errCh chan error, conf *util.Config) error {
	port := conf.ServerPort
	addr := fmt.Sprintf("%s:%d", conf.ServerAddr, port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		c, err := ln.Accept()
		errCh <- err

		go handleStageConnections(c, conf)
	}
}

// handleStage handles stages
func handleStageConnections(c net.Conn, conf *util.Config) error {
	reqbuf := bufio.NewReader(c)

	// decrypt data here
	if conf.IsServer {
		// read connect info
		buf := make([]byte, 32)
		n, err := io.ReadAtLeast(c, buf, 1)
		if err != nil {
			if err != io.EOF {
				return err
			}
		}

		pt, err := conf.Encryption.Decrypt(buf[:n])
		// most of annoying requests are blocked here if cipheretext length is wrong
		// or, of course, bad credentials a client provided
		if err != nil {
			loggingInfo(context.Background(), "%v: annoying requests or bad password from %v", err, c.RemoteAddr())
			return nil
		}

		r := bytes.NewReader(pt)
		sock, err := parseHeader(r, false, int(n))

		// this is important. use read buffer so that we can refresh data
		sock.reqbuf = c
		loggingInfo(context.Background(), "connecting from %v", c.RemoteAddr())
		if err != nil {
			return err
		}

		return remoteRead(c, sock)
	}

	errCh := make(chan error, 2)

	head := make([]byte, 3)

	go func(c net.Conn, h []byte, rd io.Reader, ech chan error) {

		// read version, auth methods and reserved field
		_, err := io.ReadAtLeast(reqbuf, h, 2)
		ech <- err

		// say hi to a client if everything fine.
		_, er := c.Write([]byte{5, 0})

		ech <- er

	}(c, head, reqbuf, errCh)

	if err := waitError(errCh, 2); err != nil {
		return err
	}

	if head[0] != uint8(5) { // seems illegal request?
		return nil
	}

	ctx := newContext(context.Background(), newID()) // context for logging.

	sock, err := parseHeader(c, true, 0)

	if err != nil {
		// could not parse a header?
		return handleNetworkError(c, err)
	}

	sock.ctx = ctx // stock context

	// send dumb data to a client
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 1, 1}); err != nil {
		return err
	}

	switch { // handle stagings
	case uint8(head[1]) == CONNECTCMD:
		loggingInfo(sock.ctx, "stream")

		if conf.IsClient {
			// encrypt  data and send it to remote and get response back
			if e := handleConnect(c, sock, conf); e != nil {
				loggingInfo(ctx, "ERROR: %v", e)
			}
		} else {
			// read and decrypt
		}
	case uint8(head[1]) == BINDCOMD:
		return handleBind(c, sock, conf)
	case uint8(head[1]) == UDPASSOCIATECMD: // TODO
		loggingInfo(ctx, "associate udp")
		handleBindUdp(c)
		return nil
	default:
		loggingInfo(sock.ctx, "unknow command %v", head)
		return errors.New(fmt.Sprintf("handleStage: unknown command: %v", head[1]))
	}
	return nil
}

// remoteRead reads data from clients and send it back to clients.
func remoteRead(w io.Writer, sock *socket) error {
	dst, err := sock.dial()

	if err != nil {
		loggingInfo(context.Background(), "ERROR: %v", err)
		return handleNetworkError(dst, err)
	}

	defer dst.Close()

	errCh := make(chan error, 2)
	go writeToSock(dst, sock.reqbuf, errCh, sock.ctx)
	go writeToSock(w, dst, errCh, sock.ctx)
	return waitError(errCh, 2)
}

func waitError(errCh chan error, g int) error {
	if g < 0 {
		return nil
	}
	for i := 0; i < g; i++ {
		e := <-errCh
		if e != nil {
			return e
		}
	}
	return nil
}

type client interface {
	Write([]byte) (int, error)
}

func handleNetworkError(c client, e error) error {

	err := e.Error()

	switch {
	case strings.Contains(err, "connection refused"):
		writeSocks5Header(c, "", CONNECTIONREFUSED)
	case strings.Contains(err, "network is unreachable"):
		writeSocks5Header(c, "", NETWORKUNREACHABLE)
	case strings.Contains(err, "unknow address type"):
		writeSocks5Header(c, "", ADDRESSNOTSUPPORTED)
	}
	if tcp, ok := c.(closeWriter); ok {
		tcp.CloseWrite()
	}
	return e
}

// handleStreams takes cli that is io.Writer and *socket.
func handleStream(cli client, sock *socket) error {
	dstconn, err := sock.dial()

	if err != nil {
		return handleNetworkError(cli, err) // TODO: IPv6 doesn't work
	}

	defer dstconn.Close()

	// if everything fine send GRANT status.
	if err := writeSocks5Header(cli, sock.String(), GRANTED); err != nil {
		return handleNetworkError(cli, err)
	}

	errCh := make(chan error, 2)

	go writeToSock(dstconn, sock.reqbuf, errCh, sock.ctx)
	go writeToSock(cli, dstconn, errCh, sock.ctx)

	// wait for it..
	return waitError(errCh, 2)
}

// creteRemoteSecureSocket creates a gateway to a remote server.
func handleConnect(c net.Conn, sock *socket, conf *util.Config) error {
	var b []byte

	buf := bytes.NewBuffer(b)

	var header []byte
	// rebuild socks request
	switch {
	case sock.domain != nil:
		header = []byte{5, 0, 0, DOMAIN}
	case sock.ip.To4() != nil:
		header = []byte{5, 0, 0, IPv4}
	case sock.ip.To16() != nil:
		header = []byte{5, 0, 0, IPv6}
	}

	// header
	if _, err := buf.Write([]byte(header)); err != nil {
		return err
	}

	if sock.domain != nil { // domain
		if err := buf.WriteByte(uint8(len(sock.domain))); err != nil {
			return err
		}
		if _, err := buf.Write(sock.domain); err != nil {
			return err
		}
	} else { // ip
		if _, err := buf.Write([]byte(sock.ip)); err != nil {
			return err
		}
	}

	// port
	if _, err := buf.Write([]byte{byte(sock.port >> 8), byte(sock.port & 0xff)}); err != nil {
		return err
	}

	rmsock := &socket{} // create remote socket

	rmsock.network = "tcp"

	if host, p, err := net.SplitHostPort(conf.Servers[0]); err != nil {
		return errors.New(fmt.Sprintf("bad remote server: %v", rmsock))
	} else {
		rmsock.ip = net.ParseIP(host)
		if iport, err := strconv.Atoi(p); err != nil {
			return err
		} else {
			rmsock.port = iport
		}
	}

	if rmsock == nil {
		return errors.New(fmt.Sprintf("bad remote server: %v", rmsock))
	}

	dst, err := rmsock.dial()

	if err != nil {
		return handleNetworkError(c, err) // may be server donw, server unreachable ...
	}
	cpt, err := conf.Encryption.Encrypt(buf.Bytes())

	if err != nil {
		panic(err)
	}

	if _, err := dst.Write(cpt); err != nil {
		return err
	}

	defer dst.Close()

	errch := make(chan error, 1)

	/// wait for server's reply
	go writeToSock(dst, sock.reqbuf, errch, context.Background())
	go writeToSock(c, dst, errch, context.Background())

	return waitError(errch, 1)
}

type closeWriter interface {
	CloseWrite() error
}

// writeToSock copies from src to dst until either io.EOF.
func writeToSock(dst io.Writer, src io.Reader, errch chan error, ctx context.Context) {
	_, err := io.Copy(dst, src)

	if ctx == nil {
		ctx = context.Background()
	}

	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}

	errch <- err
}

func handleBind(c net.Conn, sock *socket, conf *util.Config) error {
	loggingInfo(sock.ctx, "portbings: %v", sock)
	return handleConnect(c, sock, conf)
}

func handleBindUdp(c net.Conn) error {
	return errors.New("bind udp")
}

type responseBuffer []byte

var hang = func(i ...interface{}) { log.Println("hang ", i) }

// parseHeader parses header and gives a socket back.
// unknow requests should be blocked here.
func parseHeader(r io.Reader, islocal bool, offset int) (*socket, error) {
	sock := &socket{}

	sock.reqbuf = r

	addrt := []byte{0, 0, 0, 0}
	if _, err := io.ReadAtLeast(r, addrt, 4); err != nil {
		if err != io.EOF {
			return nil, err
		}
	}

	sock.network = "tcp"

	ctx := context.Background()

	// get a destination address.
	switch addrt[3] {
	case IPv4:
		rdb := make([]byte, 4)
		if _, err := io.ReadFull(r, rdb); err != nil {
			if err != io.EOF {
				return nil, err
			}
		}
		sock.ip = net.IP(rdb[:4]).To4()
		sock.addrType = IPv4
	case IPv6:
		rdb := make([]byte, 16)
		if _, err := io.ReadFull(r, rdb); err != nil {
			if err != io.EOF {
				return nil, err
			}
		}
		sock.ip = net.IP(rdb[:16]).To16()
		sock.addrType = IPv6
	case DOMAIN:
		// TODO: dns resolver.
		// note: first byte is a length of domain.
		dlen := make([]byte, 1) // first byte is a length of doamin.
		if _, err := io.ReadAtLeast(r, dlen, 1); err != nil {
			if err != io.EOF {
				return nil, err
			}
		}
		if islocal {
			dom := make([]byte, int(dlen[0]))
			if _, err := io.ReadFull(r, dom); err != nil {
				if err != io.EOF {
					return nil, err
				}
			}
			sock.domain = dom
		} else { // dns should be resolved in remote.

			dom := make([]byte, int(dlen[0]))

			if _, err := io.ReadAtLeast(r, dom, 1); err != nil {
				if err != io.EOF {
					return nil, err
				}
			}
			ips, err := util.DnsResolver(string(dom), sock.ctx)
			if err != nil {
				// TODO: TODO handle errors
				panic(err)
			}
			ip := net.IP(ips[0])

			switch {
			case ip.To4() != nil:
				sock.ip = ip.To4()
			case ip.To16() != nil:
				sock.ip = ip.To16()
			}
		}
	default:
		return nil, errors.New(
			fmt.Sprintf("parseHeader: unknow address type. wrong password or method %v", addrt))
	}

	// port in two bytes in network order
	p := []byte{0, 0}
	if _, err := io.ReadFull(r, p); err != nil {
		panic(err)
	}
	sock.port = int(p[0])<<8 | int(p[1])
	if sock.domain != nil {
		loggingInfo(ctx, "domain: %v:%v", string(sock.domain), sock.port)
	} else {
		loggingInfo(ctx, "resolved ip: %v", sock)
	}
	return sock, nil
}

// writeSocks5Header writes a header for socks5 clients.
func writeSocks5Header(w io.Writer, addr string, msg uint8) error {
	var host net.IP
	var port uint16
	var addrtype uint8
	var ip []byte

	if addr != "" {
		host, port = splitHostPort(addr)
	}

	switch {
	case host == nil:
		addrtype = 0
		ip = nil
	case host.To4() != nil:
		addrtype = IPv4
		ip = []byte(host.To4())
	case host.To16() != nil:
		addrtype = IPv6
		ip = []byte(host.To16())
	}

	header := make([]byte, 6+len(ip))
	header[0] = uint8(5)
	header[1] = msg
	header[2] = 0
	header[3] = addrtype

	copy(header[4:], ip)

	header[4+len(ip)] = byte(port >> 8)
	header[4+len(ip)+1] = byte(port & 0xff)
	_, err := w.Write(header)
	return err
}

func splitHostPort(hp string) (net.IP, uint16) {
	host, p, err := net.SplitHostPort(hp)
	if err != nil {
		// port missing error
		return nil, 0
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		panic(err)
	}
	return net.ParseIP(host), uint16(port)
}
