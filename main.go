package main

import (
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
)

// this program compares transfert speed of the Golang http server (and client) between HTTP/2 and HTTP/3 versions
// usage: run with no argument to do a test with 10G of data
// use the "-s" option to be in server only mode and use another program like curl (or https://nspeed.app) to test
// locally or over the wire

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

var tlsConfig *tls.Config

func init() {
	InitBigChunk(time.Now().Unix())
	tlsConfig = generateTLSConfig()
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
	if method == "GET" {
		match := StreamPathRegexp.FindStringSubmatch(r.URL.Path[1:])
		if len(match) == 2 {
			n, err := strconv.ParseInt(match[1], 10, 64)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			streamBytes(w, r, n)
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
func streamBytes(w http.ResponseWriter, r *http.Request, size int64) {

	// the buffer we use to send data
	var chunkSize int64 = 256 * 1024 // 256KiB chunk (sweet spot value may depend on OS & hardware)
	if chunkSize > MaxChunkSize {
		log.Fatal("chunksize is too big")
	}
	chunk := BigChunk[:chunkSize]

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	//fmt.Printf("header sent to %s: %s\n", r.RemoteAddr, r.URL)

	startTime := time.Now()

	size_tx := int64(0)
	hasEnded := false
	var numChunk = size / chunkSize
	for i := int64(0); i < numChunk; i++ {
		n, err := w.Write(chunk)
		size_tx = size_tx + int64(n)
		if err != nil {
			hasEnded = true
			break
		}
	}
	if size%chunkSize > 0 && !hasEnded {
		n, _ := w.Write(chunk[:size%chunkSize])
		size_tx = size_tx + int64(n)
	}

	f := w.(http.Flusher)
	f.Flush()

	duration := time.Since(startTime)
	fmt.Printf("server sent %d bytes in %s = %s (%d chunks) to %s\n", size_tx, duration, FormatBitperSecond(duration.Seconds(), size_tx), chunkSize, r.RemoteAddr)
}

// create a H2/H3 HTTP server, wait for ctx.Done(), shutdown the server and signal the WaitGroup
func createServer(ctx context.Context, host string, port int, wg *sync.WaitGroup, ready chan bool) {
	wg.Add(1)
	defer wg.Done()

	listenAddr := net.JoinHostPort(host, strconv.Itoa(port))
	server := &http.Server{
		Addr:      listenAddr,
		Handler:   createHandler(),
		TLSConfig: tlsConfig,
	}
	quicConf := &quic.Config{}
	quicServer := &http3.Server{
		Addr:       listenAddr,
		TLSConfig:  tlsConfig,
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
func Download(ctx context.Context, url string, h3 bool) error {

	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	var dialer = &net.Dialer{
		Timeout:       1 * time.Second, // fail quick
		FallbackDelay: -1,              // don't use Happy Eyeballs
	}
	var netTransport = http.DefaultTransport.(*http.Transport).Clone()
	netTransport.DialContext = dialer.DialContext
	netTransport.TLSClientConfig = tlsClientConfig

	var rt http.RoundTripper = netTransport
	if h3 {
		rt = &http3.RoundTripper{TLSClientConfig: tlsClientConfig}
	}
	var body io.ReadCloser = http.NoBody

	req, err := http.NewRequestWithContext(ctx, "GET", url, body)

	if err != nil {
		return err
	}

	// client
	client := &http.Client{Transport: rt}
	resp, err := client.Do(req)
	err = fixH2H3Errors(err)

	if err == nil && resp != nil {
		fmt.Printf("receiving data with %s\n", resp.Proto)
		wm := Metrics{}
		_, err = io.CopyBuffer(&wm, resp.Body, bigbuff[:])
		err = fixH2H3Errors(err)

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

func fixH2H3Errors(err error) error {
	if err != nil {
		fmt.Println("client got error of type", reflect.TypeOf(err))
	}
	var qerr *quic.StreamError
	if errors.As(err, &qerr) && qerr.ErrorCode == 0x10c {
		// change error to context timeout
		return context.DeadlineExceeded
	}
	return err
}

// client just like "curl -o /dev/null url"
func doClient(ctx context.Context, url string, h3 bool, timeout time.Duration) error {
	fmt.Printf("downloading %s\n", url)
	if timeout > 0 {
		ctx2, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		ctx = ctx2
	}
	err := Download(ctx, url, h3)
	if err != nil {
		fmt.Printf("client error for %s: %s\n", url, err)
	}
	return err
}

var optServer = flag.Bool("s", false, "server mode only")
var optClient = flag.String("c", "", "client only mode, connect to url")
var optH3 = flag.Bool("h3", false, "use http/3 client (use with -c)")
var optCpuProfile = flag.String("cpuprof", "", "write cpu profile to file")
var optT1 = flag.Bool("t1", true, "do predifined test 1")
var optT2 = flag.Bool("t2", true, "do predifined test 2")
var optSize = flag.Uint64("b", 10000000000, "number of bytes to transfert")
var optTimeout = flag.Duration("t", 0, "timeout (in golang duration)")

func main() {

	flag.Parse()

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
		doClient(ctx, *optClient, *optH3, *optTimeout)
		return
	}

	if *optT1 {
		doClient(ctx, fmt.Sprintf("https://localhost:2222/%d", *optSize), false, *optTimeout)
	}
	if *optT2 {
		doClient(ctx, fmt.Sprintf("https://localhost:2222/%d", *optSize), true, *optTimeout)
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

// Setup a bare-bones TLS config for the server (from quic-go/examples)
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(crand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		IsCA:        true,
		NotBefore:   now,
		NotAfter:    now.AddDate(0, 0, 1), // Valid for one day
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(crand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
}
