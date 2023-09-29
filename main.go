package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type responseWriterWithSize struct {
	http.ResponseWriter
	statusCode int
	Size       int
}

func logRequest(logger *log.Logger, r *http.Request, size int, statusCode int) {
	clientIP := r.RemoteAddr
	currentTime := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	requestMethod := r.Method
	requestPath := r.URL.Path
	httpVersion := r.Proto
	logger.Printf("%s - - [%s] \"%s %s %s\" %d %d\n", clientIP, currentTime, requestMethod, requestPath, httpVersion, statusCode, size)
}

func (w *responseWriterWithSize) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriterWithSize) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.Size += n
	return n, err
}

func configureTLS(certFile, keyFile, chainFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal("Error loading certificate and key:", err)
	}

	var intermediates *x509.CertPool
	if chainFile != "" {
		chainPEM, err := ioutil.ReadFile(chainFile)
		if err != nil {
			log.Fatal("Error loading intermediate certificate chain:", err)
			return nil, err
		}
		intermediates = x509.NewCertPool()
		if !intermediates.AppendCertsFromPEM(chainPEM) {
			log.Fatal("Failed to append intermediate certificate to pool.")
			return nil, err
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		RootCAs:      intermediates,
	}

	return tlsConfig, nil
}

func main() {
	port := flag.Int("port", 8889, "Port to listen on")
    ListenIP := flag.String("ip", "127.0.0.1", "IP to listen on")
	logFile := flag.String("log", "", "Log file path (empty for stdout)")
	directory := flag.String("dir", ".", "Directory to serve")
	certFile := flag.String("cacert", "", "Path to CA certificate file for TLS (optional)")
	keyFile := flag.String("key", "", "Path to private key file for TLS (optional)")
	chainFile := flag.String("chain", "", "Path to intermediate certificate chain file for TLS (optional)")


	// Parse the command-line flags
	flag.Parse()

	var logger *log.Logger

    lf := *logFile

	if lf == "" || lf == "-" {
		logger = log.New(os.Stdout, "", 0)
	} else {
		lf, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening log file: %s\n", err)
			os.Exit(1)
		}
		logger = log.New(lf, "", 0)
	}

	dir := *directory

	if dir == "." || dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatal("Error getting current working directory:", err)
			os.Exit(1)
		}
		dir = cwd
	} else {
		dir = *directory
	}

    p := *port
    ip := *ListenIP

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		var statusCode int

		_, err := os.Stat(strings.Join([]string{dir, r.URL.Path}, "/"))

		if err != nil {
			if os.IsNotExist(err) {
				statusCode = http.StatusNotFound
			} else if os.IsPermission(err) {
				statusCode = http.StatusForbidden
			} else {
				statusCode = http.StatusInternalServerError
			}
		} else {
        	statusCode = http.StatusOK
		}

        rw := &responseWriterWithSize{w, statusCode, 0}
		http.FileServer(http.Dir(dir)).ServeHTTP(rw, r)
		logRequest(logger, r, rw.Size, statusCode)
	})

	var server *http.Server
	var tlsConfig *tls.Config
	var err error

	if *certFile != "" && *keyFile != "" {
		// TLS configuration with TLS version restriction and intermediate certificates
		tlsConfig, err = configureTLS(*certFile, *keyFile, *chainFile)

		if err != nil {
			log.Fatal("Error configuring TLS:", err)
			os.Exit(1)
		}

		server = &http.Server{
			Addr:      fmt.Sprintf("%s:%d", ip, p),
			TLSConfig: tlsConfig,
		}
		err = server.ListenAndServeTLS("", "")
	} else {
		// No TLS configuration
		server = &http.Server{
			Addr: fmt.Sprintf("%s:%d", ip, p),
		}
		err = server.ListenAndServe()
	}

	if err != nil {
		log.Fatal("Error starting server:", err)
		os.Exit(1)
	}
}
