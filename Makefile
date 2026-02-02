# Go parameters
GOCMD = go
GOBUILD = $(GOCMD) build
GOCLEAN = $(GOCMD) clean

# Binary output name
BINARY_NAME = serv

# Default target
all: build

# Build the Go program
build:
	$(GOBUILD) -o $(BINARY_NAME) -v

# Clean build files
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)