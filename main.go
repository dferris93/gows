package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type responseWriterWithSize struct {
	http.ResponseWriter
	StatusCode int
	Size       int
}

func (w *responseWriterWithSize) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriterWithSize) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.Size += n
	return n, err
}

func logRequest(logger *log.Logger, r *http.Request, size int, statusCode int) {
	currentTime := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	requestMethod := r.Method
	requestPath := r.URL.Path
	httpVersion := r.Proto
	clientIP := ""
	proxyIP := strings.Split(r.RemoteAddr, ":")[0] 

	if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
		clientIP = xForwardedFor
	} else if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
		clientIP = xRealIP
	} else {
		clientIP = proxyIP
		proxyIP = ""
	}

	if proxyIP == "" {
		logger.Printf("%s - - - [%s] \"%s %s %s\" %d %d\n", clientIP, currentTime, requestMethod, requestPath, httpVersion, statusCode, size)
	} else {
		logger.Printf("%s %s - - [%s] \"%s %s %s\" %d %d\n", proxyIP, clientIP, currentTime, requestMethod, requestPath, httpVersion, statusCode, size)
	}
}

func configureTLS(CAcertFile string, certFile string, keyFile string, clientCertAuth bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal("Error loading certificate and key:", err)
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	var CAcert *x509.CertPool

	if CAcertFile != "" {
		caPEM, err := os.ReadFile(CAcertFile)
		if err != nil {
			log.Fatal("Error loading CA certificate:", err)
			return nil, err
		}

		CAcert = x509.NewCertPool()
		if !CAcert.AppendCertsFromPEM(caPEM) {
			log.Fatal("Failed to append CA certificate to pool.")
			return nil, err
		}
		if clientCertAuth {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.ClientCAs = CAcert
		} 
		tlsConfig.RootCAs = CAcert
	}

	return tlsConfig, nil
}


func checkLink(dir string, file string, checkHardLinks bool) error {
	fullPath := filepath.Join(dir, file)
	fileInfo, err := os.Lstat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			// if a file doesn't exist we want a 404 not a 403
			return nil
		} else {
			return err
		}
	}

	if fileInfo.Mode()&os.ModeSymlink != 0 {
		linkDest, err := os.Readlink(fullPath)
		if err != nil {
			return err
		}

		abspath, err := filepath.Abs(linkDest)
		if err != nil {
			return err
		}

		if !strings.HasPrefix(abspath, 
				dir + string(filepath.Separator)) {
			return fmt.Errorf("insecure symlink: %s", file)
		}
	}

	if checkHardLinks {
		if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
			nlink := stat.Nlink
			if nlink > 1 {
				return fmt.Errorf("hardlink detected: %s", file)
			}
		}
	}

	return nil
}

func isDotFile(dir string, file string) error {
	path := filepath.Join(dir, file)
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
			if strings.HasPrefix(part, ".") {
					return fmt.Errorf("dot file detected: %s", file)
			}
	}
	return nil
}

func checkBasicAuth(r *http.Request, expectedUsername string, expectedPassword string) bool {
	username, password, ok := r.BasicAuth()
	if ok {
		if username == expectedUsername && password == expectedPassword {
			return true
		}
	}
	return false
}

func authCheck(r *http.Request, username, password string) bool {
	if username != "" && password != "" {
		return checkBasicAuth(r, username, password)
	}
	return true
}

func checkSubnet(ip string, subnet string) bool {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		log.Fatal(err)
		return false
	}
	return ipnet.Contains(net.ParseIP(ip))
}

func ipcheck(r *http.Request, allowedIPs []string) bool {
	remoteAddr := strings.Split(r.RemoteAddr, ":")[0] 
	for _, ip := range allowedIPs {
		if strings.Contains(ip, "/") {
				return checkSubnet(remoteAddr, ip)
		} else {
			if remoteAddr == ip {
				return true
			}
		}
	}
	return false
}

func isRequestAuthorized(dir, path string, allowInsecure, checkHardLinks bool) bool {
	if path != "/" {
		if !allowInsecure {
			if checkLink(dir, path, checkHardLinks) != nil || isDotFile(dir, path) != nil {
				return false
			}
		}
	}
	return true
}

func logAndReturnError(rw *responseWriterWithSize, logger *log.Logger, r *http.Request, ac bool, errorMsg string, errorCode int) {
	if !ac {
		rw.Header().Set("WWW-Authenticate", `Basic realm="Enter username and password"`)
	}
	http.Error(rw, errorMsg, errorCode)
	logRequest(logger, r, rw.Size, rw.StatusCode)
}

type multiValueFlag []string

func (m *multiValueFlag) String() string {
	return fmt.Sprintf("%v", *m)
}

func (m *multiValueFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func makeMap(f multiValueFlag) map[string]string {
	m := make(map[string]string)
	for _, header := range f {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}

	}
	return m
}


func main() {
	port := flag.Int("port", 8889, "Port to listen on")
	ListenIP := flag.String("ip", "127.0.0.1", "IP to listen on")
	logFile := flag.String("log", "", "Log file path (empty for stdout)")
	directory := flag.String("dir", ".", "Directory to serve")
	CAcertFile := flag.String("cacert", "", "Path to CA certificate file for TLS (optional).")
	certFile := flag.String("cert", "", "Path to host certificate file for TLS (optional)")
	keyFile := flag.String("key", "", "Path to private key file for TLS (optional)")
	clientCertAuth := flag.Bool("clientcertauth", false, "Require client certificate for TLS (optional)")
	username := flag.String("username", "", "Username for basic auth (optional)")
	password := flag.String("password", "", "Password for basic auth (optional)")
	checkHardLinks := flag.Bool("checkhardlinks", false, "Check for hardlinks (optional)")
	allowInsecure := flag.Bool("allowinsecure", false, "Allow insecure symlinks and files (optional)")
	allowedIPs := flag.String("allowedips", "", "Comma separated list of allowed IPs (optional)")

	var headersFlag multiValueFlag

	flag.Var(&headersFlag, "header", "HTTP headers to include in the response. Can specify multiple.")

	var redirectsFlag multiValueFlag

	flag.Var(&redirectsFlag, "redirect", "Redirects to add. Can specify multiple.")

	flag.Parse()

	headersMap := makeMap(headersFlag)
	redirectsMap := makeMap(redirectsFlag)

	var allowedIPsSlice []string

	if *allowedIPs != "" {
		allowedIPsSlice = strings.Split(*allowedIPs, ",")	
	}

	var logger *log.Logger

	lf := *logFile

	if lf == "" || lf == "-" {
		logger = log.New(os.Stdout, "", 0)
	} else {
		lf, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening log file: %s\n", err)
			os.Exit(1)
		}
		logger = log.New(lf, "", 0)
	}

	dir := filepath.Clean(*directory)

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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriterWithSize{w, http.StatusOK, 0}

		var ipc bool 
		if len(allowedIPsSlice) > 0 {
			ipc = ipcheck(r, allowedIPsSlice)
			if !ipc {
				logAndReturnError(rw, logger, r, ipc, "403 forbidden", http.StatusForbidden)
				return
			}
		}

		ac := authCheck(r, *username, *password)
		
		if !ac {
			logAndReturnError(rw, logger, r, ac, "401 unauthorized", http.StatusUnauthorized)
			return
		}

		if url, ok := redirectsMap[r.URL.Path]; ok {
			http.Redirect(rw, r, url, http.StatusFound)
			logRequest(logger, r, rw.Size, rw.StatusCode)
			return
		}
		
		path := filepath.Clean(r.URL.Path)
		if !isRequestAuthorized(dir, path, *allowInsecure, *checkHardLinks) {
			logAndReturnError(rw, logger, r, ac, "403 forbidden", http.StatusForbidden)
			return
		}

		
		fullPath := filepath.Join(dir, filepath.FromSlash(path))
		info, err := os.Stat(fullPath)
		if err != nil {
			logAndReturnError(rw, logger, r, ac, "404 not found", http.StatusNotFound)
			return
		}

		for key, value := range headersMap {
			rw.Header().Set(key, value)
		}

		if info.IsDir() {
			indexFile := filepath.Join(fullPath, "index.html")
			if _, err := os.Stat(indexFile); err == nil {
				http.ServeFile(rw, r, indexFile)
				return
			} else {
				http.FileServer(http.Dir(dir)).ServeHTTP(rw, r)
			}
		} else {
			http.ServeFile(rw, r, fullPath)
		}
		
		logRequest(logger, r, rw.Size, rw.StatusCode)

	})

	var server *http.Server
	var tlsConfig *tls.Config
	var err error

	p := *port
	ip := *ListenIP

	if *certFile != "" && *keyFile != "" {
		tlsConfig, err = configureTLS(*CAcertFile, *certFile, *keyFile, *clientCertAuth)
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
