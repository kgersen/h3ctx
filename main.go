package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"reflect"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/logging"
	"golang.org/x/net/http2"
)

// this program compares transfert speed of the Golang http server (and client) between HTTP/2 and HTTP/3 versions
// usage: run with no argument to do a test with 10G of data
// use the "-s" option to be in server only mode and use another program like curl (or https://nspeed.app) to test
// locally or over the wire
// use ther "-t duration" to limit the test duration from the client side.
// use ther "-st duration" to limit the test duration from the server side.
// see "-h" also.

// build a 1MiB buffer of random data
const MaxChunkSize = 1024 * 1024 // warning : 1 MiB // this will be allocated in memory
var BigChunk [MaxChunkSize]byte

var bigbuff [16 * 1024 * 1024]byte

func InitBigChunk(seed int64) {
	rng := rand.New(rand.NewSource(seed))
	for i := int64(0); i < MaxChunkSize; i++ {
		BigChunk[i] = byte(rng.Intn(256))
	}
}

var serverTlsConfig, clientTlsConfig *tls.Config

func init() {
	InitBigChunk(time.Now().Unix())
	var err error
	serverTlsConfig, clientTlsConfig, err = generateTLSConfig()
	if err != nil {
		panic(err)
	}
}

// implements io.Discard
type Metrics struct {
	mu          sync.Mutex
	StepSize    int64
	StartTime   time.Time
	ElapsedTime time.Duration
	TotalRead   int64
	ReadCount   int64
}

// Write - performance sensitive, don't do much here
// it's basically a io.Discard with some metrics stored
func (wm *Metrics) Write(p []byte) (int, error) {
	n := len(p)
	s := int64(n)
	wm.mu.Lock()
	defer wm.mu.Unlock()

	// store bigest step size
	if s > wm.StepSize {
		wm.StepSize = s
	}

	wm.TotalRead += s

	// store elasped time
	if wm.ReadCount == 0 {
		wm.StartTime = time.Now()
	} else {
		wm.ElapsedTime = time.Since(wm.StartTime)
	}
	wm.ReadCount++
	return n, nil
}

// regexp to parse url
var StreamPathRegexp *regexp.Regexp

func createHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	var handler http.Handler = mux
	return handler
}

// handle the only route: '/number' which send <number> bytes of random data
func rootHandler(w http.ResponseWriter, r *http.Request) {

	//fmt.Printf("request from %s: %s\n", r.RemoteAddr, r.URL)
	method := r.Method
	if method == "" {
		method = "GET"
	}

	var timeout time.Duration = 0
	var err error
	// parse an optionnal "timeout" query parameter in Go time.Duration syntax
	if sTimeout := r.URL.Query().Get("timeout"); sTimeout != "" {
		timeout, err = time.ParseDuration(sTimeout)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}

	if method == "GET" {
		match := StreamPathRegexp.FindStringSubmatch(r.URL.Path[1:])
		if len(match) == 2 {
			n, err := strconv.ParseInt(match[1], 10, 64)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			streamBytes(w, r, n, timeout)
			return
		} else {
			http.Error(w, "Not found (no regexp match)", http.StatusNotFound)
			return
		}
	}
	if method == "POST" {
		startedAt := time.Now()
		fmt.Printf("%s - starting Upload (%s) of %d bytes from %s\n", startedAt.Format("2006-01-02 15:04:05"), r.Proto, r.ContentLength, r.RemoteAddr)
		n, err := io.CopyBuffer(io.Discard, r.Body, bigbuff[:])
		endedAt := time.Now()
		dur := endedAt.Sub(startedAt)
		if err != nil {
			http.Error(w, fmt.Sprintf("upload error %v", err), http.StatusInternalServerError)
		}
		report := fmt.Sprintf("%s - received %d bytes in %s (%s) with %s from  %s (expected %d bytes)\n",
			endedAt.Format("2006-01-02 15:04:05"),
			n,
			dur,
			FormatBitperSecond(dur.Seconds(), n),
			r.Proto, r.RemoteAddr, r.ContentLength)
		fmt.Println(report)
		w.Write([]byte(report))
		return

	}
	http.Error(w, "unhandled method", http.StatusBadRequest)
}

// send 'size' bytes of random data
func streamBytes(w http.ResponseWriter, r *http.Request, size int64, timeout time.Duration) {

	// the buffer we use to send data
	var chunkSize int64 = 256 * 1024 // 256KiB chunk (sweet spot value may depend on OS & hardware)
	if chunkSize > MaxChunkSize {
		log.Fatal("chunksize is too big")
	}
	chunk := BigChunk[:chunkSize]

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	//fmt.Printf("header sent to %s: %s\n", r.RemoteAddr, r.URL)

	if timeout > 0 {
		rc := http.NewResponseController(w)
		err := rc.SetWriteDeadline(time.Now().Add(timeout))
		if err != nil {
			fmt.Printf("can't SetWriteDeadline: %s\n", err)
		}
	}

	startTime := time.Now()

	size_tx := int64(0)
	hasEnded := false
	var writeErr error
	var numChunk = size / chunkSize
	for i := int64(0); i < numChunk; i++ {
		n, err := w.Write(chunk)
		size_tx = size_tx + int64(n)
		if err != nil {
			hasEnded = true
			writeErr = err
		}
	}
	if size%chunkSize > 0 && !hasEnded {
		n, err := w.Write(chunk[:size%chunkSize])
		size_tx = size_tx + int64(n)
		if err != nil {
			writeErr = err
		}
	}

	// f := w.(http.Flusher)
	// f.Flush()

	duration := time.Since(startTime)
	fmt.Printf("server sent %d bytes in %s = %s (%d chunks) to %s (server error : %s)\n", size_tx, duration, FormatBitperSecond(duration.Seconds(), size_tx), chunkSize, r.RemoteAddr, writeErr)
}

// create a H2/H3 HTTP server, wait for ctx.Done(), shutdown the server and signal the WaitGroup
func createServer(ctx context.Context, host string, port int, wg *sync.WaitGroup, ready chan bool) {
	wg.Add(1)
	defer wg.Done()

	listenAddr := net.JoinHostPort(host, strconv.Itoa(port))
	server := &http.Server{
		Addr:      listenAddr,
		Handler:   createHandler(),
		TLSConfig: serverTlsConfig,
	}
	quicConf := &quic.Config{}
	quicServer := &http3.Server{
		Addr:       listenAddr,
		TLSConfig:  serverTlsConfig,
		QuicConfig: quicConf,
		Handler:    server.Handler,
	}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := quicServer.SetQuicHeaders(w.Header())
		if err != nil {
			log.Fatal(err)
		}
		quicServer.Handler.ServeHTTP(w, r)
	})

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatalf("cannot listen (tcp) to %s: %s", server.Addr, err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", quicServer.Addr)
	if err != nil {
		log.Fatalf("cannot ResolveUDPAddr %s: %s", server.Addr, err)
	}
	ln3, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("cannot listen (udp) to %s: %s", server.Addr, err)
	}
	// this will wait for ctx.Done then shutdown the server
	go func() {
		<-ctx.Done()
		fmt.Printf("server %s shuting down\n", listenAddr)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	// signal the server is listening (so client(s) can start)
	ready <- true

	//spawn h3 (yeah this is not a clean way to do this...)
	go func() {
		quicServer.Serve(ln3)
	}()
	// wait on h2
	err = server.ServeTLS(ln, "", "")

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("cannot serve %s: %s", server.Addr, err)
	}
}

// http client, download the url to 'null' (discard)
func Download(ctx context.Context, url string, h3 bool, ipVersion int) error {

	//assert ipVersion = 0 || 4 || 6

	tlsClientConfig := clientTlsConfig
	if *optSkipTLS {
		clientTlsConfig.InsecureSkipVerify = true
	}
	var dialer = &net.Dialer{
		Timeout:       1 * time.Second, // fail quick
		FallbackDelay: -1,              // don't use Happy Eyeballs
	}
	var netTransport = http.DefaultTransport.(*http.Transport).Clone()
	// custom DialContext that can force IPv4 or IPv6
	netTransport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		if network == "udp" || network == "tcp" {
			if ipVersion != 0 {
				network += strconv.Itoa(ipVersion)
			}
		}
		return dialer.DialContext(ctx, network, address)
	}
	netTransport.TLSClientConfig = tlsClientConfig

	var rt http.RoundTripper = netTransport
	if h3 {
		// with use http3.RoundTripper but it doesnt expose its quic.Transport member field so we must use our own
		var qTransport *quic.Transport
		defer func() {
			if qTransport != nil {
				fmt.Println("closing local quic transport")
				qTransport.Close()
				qTransport = nil
			}
		}()

		qt := &quicTracer{}
		rt = &http3.RoundTripper{
			TLSClientConfig: tlsClientConfig,
			QuicConfig: &quic.Config{
				Tracer: qt.TracerForConnection,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				// this dialer respect ipv6/ipv4 preference
				network := "udp"
				udpAddr, err := netTransport.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				if qTransport == nil {
					// check for Zone on IPv6 link-local for instance, some OS might need the Zone too
					udpConn, err := net.ListenUDP(network, nil)
					if err != nil {
						return nil, err
					}
					qTransport = &quic.Transport{Conn: udpConn}
				}
				// use same dialer as other http version

				fmt.Printf("HTTP3 dialing %s -> %s\n", addr, udpAddr.RemoteAddr().String())
				return qTransport.DialEarly(ctx, udpAddr.RemoteAddr(), tlsCfg, cfg)
			},
		}
	}
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			if connInfo.Conn != nil {
				fmt.Println("client connected to ", connInfo.Conn.RemoteAddr())
			}
		},
	}
	ctx = httptrace.WithClientTrace(ctx, trace)

	var body io.ReadCloser = http.NoBody
	req, err := http.NewRequestWithContext(ctx, "GET", url, body)

	if err != nil {
		return err
	}

	// client
	client := &http.Client{Transport: rt}
	resp, err := client.Do(req)
	//err = fixH2H3Errors("c->s", err)

	if err == nil && resp != nil {
		fmt.Printf("receiving data with %s\n", resp.Proto)
		wm := Metrics{}
		_, err = io.CopyBuffer(&wm, resp.Body, bigbuff[:])
		err = fixH2H3Errors("s->c", err)

		resp.Body.Close()

		timedOut := "no"
		if errors.Is(err, io.EOF) {
			err = nil
			timedOut = "server timeout"
		}
		if errors.Is(err, context.DeadlineExceeded) {
			err = nil

			timedOut = "client timeout"
		}
		if err != nil {
			return err
		}
		fmt.Printf("client received %d bytes in %v = %s, %d write ops, %d buff (timeout: %s)\n", wm.TotalRead, wm.ElapsedTime, FormatBitperSecond(wm.ElapsedTime.Seconds(), wm.TotalRead), wm.ReadCount, wm.StepSize, timedOut)
	}
	return err
}

// try to unify differences between http/1, http/2, http/3 behaviors
// when a client or server timeout occured
func fixH2H3Errors(source string, err error) error {
	if err != nil {
		fmt.Printf("%s: client got error of type %s\n", source, reflect.TypeOf(err))
	} else {
		fmt.Printf("%s :client got no error\n", source)
	}

	/*
		from nspeed tests:
		   net/http errors returned in case of timeouts:
		   method:
		      client.Do (c->s) then io.Read response body (s->c)
		      we catch the err after the .Do and the one after .Read
		      c->s : we set a timer so the timeout happen during the .Do
		      s->c : we set a timer so the timeout happen during the .Read

		   client side timeouts:
		   caused by a http.Request with a context deadline

		   http/1.1:
		   	c->s: context deadline exceeded type: *url.Error
		   	s->c: context deadline exceeded type: context.deadlineExceededError
		   http/1.1 + tls:
		   	c->s: context deadline exceeded type: *url.Error
		   	s->c: context deadline exceeded type: context.deadlineExceededError
		   http/2:
		   	c->s: context deadline exceeded type: *url.Error
		   	s->c: context deadline exceeded type: context.deadlineExceededError
		   http/3:
		   	c->s: stream 0 canceled by local with error code 268 *url.Error
		   	s->c: stream 0 canceled by local with error code 268 *quic.StreamError

		   server side timeouts:
		   caused by a http.Server.WriteTimeout or ReadTimeout/ReadHeaderTimeout
		   or
		   http.NewResponseController.SetWriteDeadline/SetReadDeadline

		   http/1.1:
		     c->s: no error ! (must check how many of the Body was sent to detect the timeout)
		     s->c: io.ErrUnexpectedEOF
		   http/1.1 + tls:
		     c->s: "write: connection reset by peer"  type: *url.Error
		     s->c: "tls: bad record MAC" type: *tls.permanentError
		   http/2:
		     c->s: "stream error: stream ID 1; INTERNAL_ERROR; received from peer" type: *url.Error
		     s->c: "stream ID 1; INTERNAL_ERROR; received from peer" type: http2.StreamError
		   http/3:
		     c->s: WriteTimeout & ReadTimeout/ReadHeaderTimeout not yet tested
		     s->c: nothing reported client side (bug?), deadline exceeded server side

	*/

	// http/3 client : context.DeadlineExceeded returns a quic.StreamError with ErrorCode == 0x10c
	var qerr *quic.StreamError
	if errors.As(err, &qerr) {
		if qerr.ErrorCode == quic.StreamErrorCode(http3.ErrCodeRequestCanceled) {
			// change error to context timeout
			return context.DeadlineExceeded
		}
		fmt.Println("quic.ErrorCode = ", reflect.TypeOf(err))
	}
	// http/2 server timeout return: "stream error: stream ID x; INTERNAL_ERROR; received from peer"
	if h2err, ok := err.(http2.StreamError); ok {
		// don't change if not remote
		if h2err.Cause == nil || (h2err.Cause == nil && h2err.Cause.Error() != "received from peer") {
			return err
		}
		if h2err.Code == http2.ErrCodeInternal {
			fmt.Println("h2 stream error changed to ECONNRESET")
			return syscall.ECONNRESET
		}
		if h2err.Code == http2.ErrCodeStreamClosed {
			fmt.Println("h2 stream error changed to ErrUnexpectedEOF")
			return io.ErrUnexpectedEOF // we micmic http/1.1
		}
	}

	return err
}

// client just like "curl -o /dev/null url"
func doClient(ctx context.Context, url string, h3 bool, timeout time.Duration, ipVersion int) error {
	fmt.Printf("downloading %s\n", url)
	if timeout > 0 {
		ctx2, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		ctx = ctx2
	}
	err := Download(ctx, url, h3, ipVersion)
	if err != nil {
		fmt.Printf("client error for %s: %s\n", url, err)
	}
	return err
}

var optServer = flag.Bool("s", false, "server mode only")
var optClient = flag.String("c", "", "client only mode, connect to url")
var optSkipTLS = flag.Bool("k", false, "insecure/skip tls verification (client only mode)")
var optH3 = flag.Bool("h3", false, "use http/3 client (use with -c)")
var optCpuProfile = flag.String("cpuprof", "", "write cpu profile to file")
var optH2 = flag.Bool("noh2", false, "skip HTTP/2 test")
var optT2 = flag.Bool("noh3", false, "skip HTTP/3 test")
var optSize = flag.Uint64("b", 10000000000, "number of bytes to transfert")
var optTimeout = flag.Duration("t", 8*time.Second, "client timeout (in golang duration)")
var optSTimeout = flag.Duration("st", 0, "server timeout (in golang duration)")

var optIPv4 = flag.Bool("4", false, "force IPv4")
var optIPv6 = flag.Bool("6", false, "force IPv6")

func main() {

	flag.Parse()
	ipVersion := 0
	if *optIPv4 && *optIPv6 {
		log.Fatal("cant force both IPv4 and IPv6")
	}
	if *optIPv4 {
		ipVersion = 4
	}
	if *optIPv6 {
		ipVersion = 6
	}

	if *optCpuProfile != "" {
		runtime.SetBlockProfileRate(1)
		f, err := os.Create(*optCpuProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer func() {
			//fmt.Println("StopCPUProfile")
			pprof.StopCPUProfile()
		}()
	}

	StreamPathRegexp = regexp.MustCompile("^(" + "[0-9]+" + ")$")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

	if *optClient == "" {
		ready := make(chan bool)

		//create a server
		go createServer(ctx, "", 2222, &wg, ready)
		<-ready
		fmt.Printf("server created and listening at %s (tcp/h2) and %s (quic/h3)\n", "2222", "2222")

		// if server mode, just wait forever for something else to cancel
		if *optServer {
			fmt.Printf("server mode on\n")
			<-ctx.Done()
			return
		}
	} else {
		doClient(ctx, *optClient, *optH3, *optTimeout, ipVersion)
		return
	}

	url := fmt.Sprintf("https://localhost:2222/%d", *optSize)
	if *optSTimeout > 0 {
		url += "?timeout=" + (*optSTimeout).String()
	}
	if !*optH2 {
		doClient(ctx, url, false, *optTimeout, ipVersion)
		fmt.Println()
	}
	if !*optT2 {
		doClient(ctx, url, true, *optTimeout, ipVersion)
		fmt.Println()
	}
	cancel()
	wg.Wait()
}

// human friendly formatting stuff

// FormatBitperSecond format bit per seconds in human readable format
func FormatBitperSecond(elapsedSeconds float64, totalBytes int64) string {
	// nyi - fix me
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("recovered from divide by zero")
		}
	}()
	speed := "(too fast)"
	if elapsedSeconds > 0 {
		speed = ByteCountDecimal((int64)(((float64)(totalBytes)*8.0)/elapsedSeconds)) + "bps"
	}
	return speed
}

// ByteCountDecimal format byte size to human readable format (decimal units)
// suitable to append the unit name after (B, bps, etc)
func ByteCountDecimal(b int64) string {
	s, u := byteCount(b, 1000, "kMGTPE")
	return s + " " + u
}

// copied from : https://programming.guide/go/formatting-byte-size-to-human-readable-format.html
func byteCount(b int64, unit int64, units string) (string, string) {
	if b < unit {
		return fmt.Sprintf("%d", b), ""
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	if exp >= len(units) {
		return fmt.Sprintf("%d", b), ""
	}
	return fmt.Sprintf("%.1f", float64(b)/float64(div)), units[exp : exp+1]
}

// https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251
func generateTLSConfig() (serverTLSConf *tls.Config, clientTLSConf *tls.Config, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(crand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(crand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(crand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(crand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, nil, err
	}

	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	certpool, err := x509.SystemCertPool() //x509.NewCertPool()
	if err != nil {
		return nil, nil, err
	}
	certpool.AppendCertsFromPEM(caPEM.Bytes())
	clientTLSConf = &tls.Config{
		RootCAs: certpool,
	}

	return
}

type quicTracer struct {
	logging.NullTracer
}

func (t *quicTracer) TracerForConnection(context.Context, logging.Perspective, logging.ConnectionID) logging.ConnectionTracer {
	return &quicConnectionTracer{}
}

type quicConnectionTracer struct {
	logging.NullConnectionTracer
}

func (t *quicConnectionTracer) StartedConnection(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
	fmt.Printf("QUIC: connected to %s from %s (ids=%s-%s)\n", remote, local, srcConnID, destConnID)
}
