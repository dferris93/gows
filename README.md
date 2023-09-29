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
Usage of ./gows:
  -cacert string
        Path to CA certificate file for TLS (optional)
  -chain string
        Path to intermediate certificate chain file for TLS (optional)
  -dir string
        Directory to serve (default ".")
  -ip string
        IP to listen on (default "127.0.0.1")
  -key string
        Path to private key file for TLS (optional)
  -log string
        Log file path (empty for stdout)
  -port int
        Port to listen on (default 8889)
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

/gows --cacert server.crt --key server.key --port 8443
```

## Notes

* I have not tested TLS with an intermediary certificate chain at all.
* TLS is locked to a minimum of version 1.2.  I really don't recommend changing this.
* Go's http.Dir is not security conscious at all.  It will follow sym links out of your directory tree as well as serving every file in whatever dir you give it.
