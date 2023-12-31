# Simple HTTP Based Go File server

This is a simple go program that will serve files in a specified directory over HTTP.

## Getting Started

### Prerequisites

To run this program, you'll need to have [Go](https://golang.org/dl/) installed on your computer.

I used go 1.18, which is the Ubuntu 20.04 default.

### Installation

```
git clone https://github.com/dferris93/gows.git
cd gows
make
```

### Running
By default, gows will run on 127.0.0.1:8889

Once, the program is running, point your browser to http://127.0.0.1:8889

## Useage

```
  -allowedips string
    	Comma separated list of allowed IPs (optional)
  -allowinsecure
    	Allow insecure symlinks and files (optional)
  -cacert string
    	Path to CA certificate file for TLS (optional)
  -cert string
    	Path to CA certificate file for TLS (optional)
  -checkhardlinks
    	Check for hardlinks (optional)
  -clientcertauth
    	Require client certificate for TLS (optional)
  -dir string
    	Directory to serve (default ".")
  -header value
    	HTTP headers to include in the response. Can specify multiple.
  -ip string
    	IP to listen on (default "127.0.0.1")
  -key string
    	Path to private key file for TLS (optional)
  -log string
    	Log file path (empty for stdout)
  -password string
    	Password for basic auth (optional)
  -port int
    	Port to listen on (default 8889)
  -redirect value
    	Redirects to add. Can specify multiple.
  -username string
    	Username for basic auth (optional)

```

## Example

* Serve files in $HOME/public_html to the entire world on port 8080

```
./gows -dir $HOME/public_html -ip 0.0.0.0 -port 8080 
```

* Serve files in $HOME/public_html to the entire world on port 8080 and log to $HOME/access_log

```
./gows -dir $HOME/public_html -ip 0.0.0.0 -port 8080 -log $HOME/access_log
```

* Make a self signed TLS key pair and serve with it
```
openssl genpkey -algorithm RSA -out server.key
openssl req -new -x509 -key server.key -out server.crt -days 365

<answer the questions needed for the CSR>

./gows --cacert server.crt --key server.key --port 8443

```

* Use http basic auth
```
./gows --username admin --password admin 
```

* Use http basic auth with TLS
```
./gows --cacert server.crt --key server.key --username admin --password admin
```

* TLS cert auth
```
 openssl genpkey -algorithm RSA -out ca-key.pem
 openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 3650 -subj "/CN=My CA"
 openssl genpkey -algorithm RSA -out server-key.pem
 openssl req -new -key server-key.pem -out server-csr.pem -subj "/CN=localhost"
 openssl x509 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365
 openssl genpkey -algorithm RSA -out client-key.pem
 openssl req -new -key client-key.pem -out client-csr.pem -subj "/CN=Client"
 openssl x509 -req -in client-csr.pem -CA

 ./gows -cacert ca-cert.pem -cert server-cert.pem -key server-key.pem --clientcertauth

#And then on the client
curl https://localhost:8889/ --cert client-cert.pem --key client-key.pem  --cacert ca-cert.pem

```

* Setting Headers
```
./gows --header 'X-Test-Header:Value' --header 'X-Another-Header:Value2' 
```

* IP ACLs
```
./gows -allowedips 192.168.1.0/24,10.10.10.1,172.16.5.0/22
```

* Redirects
```
./gows --redirect '/g:https://www.google.com' -redirect '/a:https://www.amazon.com'
```

## Notes

* I have not tested TLS with an intermediary certificate chain at all, although it should work the same way it works with nginx where you have to order your ca certificates properly in the cacert file.
* TLS is locked to a minimum of version 1.2.  I really don't recommend changing this.
* By default gows will not follow symlinks outside of the directory tree.
* gows can be set to not follow hard links either.
* By default gows will not allow access to dot files
* gows will look for an index.html file, if it isn't found, it will serve the entire directory.
* custom headers will only be set if the request is successful
* If X-Forwarded-For or X-Real-IP is set, that IP will be logged as shown below.
```
ProxyIP ClientIP - - [time] "method path HTTP/Version" responseCode bytesSent
```
* If no proxy is used the log fomat will be:
```
ClientIP - - - [time] "method path HTTP/Version" responseCode bytesSent
```

Don't put private information onto the public Internet.  I'm not responsible if you manage to leak data. 
