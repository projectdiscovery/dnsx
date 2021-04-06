# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
    
all: build
build:
		$(GOBUILD) -v -ldflags="-extldflags=-static" -o "dnsx" cmd/dnsx/dnsx.go
test: 
		$(GOTEST) -v ./...
tidy:
		$(GOMOD) tidy
