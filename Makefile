.PHONY: all install-dependencies build

APPLICATION_ID=aws-credentials-broker
ORG_PATH=github.com/vndly-oss
REPO_PATH=$(ORG_PATH)/$(APPLICATION_ID)
export PATH := $(PWD)/bin:$(PATH)

export GOPATH ?= $(shell go env GOPATH)

VERSION ?= $(shell git describe --tags --dirty --always | sed -e 's/^v//g')

BIN_NAME=dist/${APPLICATION_ID}
DOCKER_IMAGE=vndly-oss/$(APPLICATION_ID):$(VERSION)

export GOBIN=$(GOPATH)/bin

all: install-dependencies build

install-dependencies:
	@dep ensure -vendor-only

.PHONY: release-binary
release-binary: install-dependencies
	@go build -o $(GOBIN)/$(APPLICATION_ID) -v $(REPO_PATH)

build:
	go build -o ${BIN_NAME}
	@echo "You can now use ./${BIN_NAME}"

docker-build:
	docker build --no-cache -t $(DOCKER_IMAGE) --build-arg VERSION=$(VERSION) .

push:
	docker push $(DOCKER_IMAGE)

deploy: docker-build push
