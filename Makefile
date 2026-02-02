# Go parameters
GOCMD = go
GOBUILD = $(GOCMD) build
GOCLEAN = $(GOCMD) clean

# Binary output name
BINARY_NAME = serv
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/man
MAN1DIR ?= $(MANDIR)/man1

# Default target
all: build

# Install the binary and man page
install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BINARY_NAME) $(DESTDIR)$(BINDIR)/$(BINARY_NAME)
	install -d $(DESTDIR)$(MAN1DIR)
	install -m 0644 man/serv.1 $(DESTDIR)$(MAN1DIR)/serv.1

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY_NAME)
	rm -f $(DESTDIR)$(MAN1DIR)/serv.1

# Build the Go program
build:
	$(GOBUILD) -o $(BINARY_NAME) -v

# Clean build files
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

.PHONY: all build clean install uninstall
