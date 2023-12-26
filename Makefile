#### Vars ####

platform = $(shell uname -s)
arch = $(shell uname -m)

prefix = $(shell pwd)/build

app_name = go-lanscan

go_deps = $(shell find . -name '*.go')

tag = $(shell git describe --tags $(shell git rev-list --tags --max-count=1))

flags ?= -ldflags '-s -w'

build_tags ?=

#### Build Objects ####
component = $(app_name)_$(tag)
component_path = $(prefix)/$(component)

linux_objects = $(component_path)_linux_$(arch)
darwin_objects = $(component_path)_darwin_$(arch)

#### Test Objects ####
test_output_dir = coverage
coverage_profile = $(test_output_dir)/coverage.profile
coverage_out = $(test_output_dir)/coverage.out

#### Gather Objects ####

ifeq ($(platform),Linux)
objects := $(linux_objects)
endif

ifeq ($(platform),Darwin)
objects := $(darwin_objects)
endif

#### Zip File Objects ####
$(foreach o,$(objects), $(eval zips += $(o).zip))

#### Rules Section ####

# builds main executable
.PHONY: all
all: $(app_name)

# builds main executable
$(prefix)/$(app_name): $(go_deps)
ifeq ($(build_tags),)
	go build $(flags) -o $(@)
else
	go build $(flags) -o $(@) -tags $(build_tags)
endif


# build main executable
.PHONY: $(app_name)
$(app_name): $(prefix)/$(app_name)

# make static build
.PHONY: static
static:
	$(MAKE) $(app_name) \
		flags="-ldflags '-linkmode external -extldflags \"-static -s -w\"'"

# installs main executable in user's default bin for golang
.PHONY: install
install:
	go install $(flags)

# cross compiles binaries for linux and darwin
$(objects): $(go_deps)
	go build $(flags) -o $(@)

# creates zips of pre-built binaries
$(zips): $(objects)
	zip -j $(@) $(@:.zip=)

# generates a relase of all pre-built binaries
.PHONY: release
release: $(zips)

# generate mocks
.PHONY: mock
mock:
	go generate ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	rm -rf $(test_output_dir)
	mkdir -p $(test_output_dir)
	go test \
		-v \
		-coverprofile $(coverage_profile) \
		-covermode=atomic \
		./...

.PHONY: print-coverage
print-coverage:
	go tool cover -func $(coverage_profile)

.PHONY: coverage
coverage:
	go tool cover -func $(coverage_profile) -o=$(coverage_out)

.PHONY: test-report
test-report:
	go tool cover -html=$(coverage_profile)

.PHONY: deps
deps:
	go install go.uber.org/mock/mockgen@latest
	curl \
		-sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
		sh -s -- -b $(shell go env GOPATH)/bin v1.55.2

# remove buid directory and installed executable
.PHONY: clean
clean:
	rm -f $(GOPATH)/bin/$(app_name)
	rm -rf $(prefix)
