GOCMD=go
GOPATH=$(shell $(GOCMD) env GOPATH))
GOTEST=$(GOCMD) test

all: test

test:
	$(GOTEST) -v ./...  -cover

