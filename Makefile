#### Vars ####

platform = $(shell uname -s)

prefix = $(shell pwd)/build

app_name = go-lanscan

go_deps = $(shell find . -name '*.go')

tag = $(shell git describe --tags $(shell git rev-list --tags --max-count=1))

flags = -ldflags '-s -w'

#### Build Objects ####
component = $(app_name)_$(tag)
component_path = $(prefix)/$(component)

linux_objects = $(component_path)_linux_amd64 \
$(component_path)_linux_arm_5 \
$(component_path)_linux_arm_6 \
$(component_path)_linux_arm_7 \
$(component_path)_linux_arm64

darwin_object = $(component_path)_darwin_amd64 \
$(component_path)_darwin_arm64

#### Gather Objects ####

ifeq ($(platform),Linux)
objects := $(linux_objects)
else
objects := $(darwin_object)
endif

#### Zip File Objects ####
$(foreach o,$(objects), $(eval zips += $(o).zip))

#### Helper Functions ####

define get_goos
$(word 3, $(subst _, ,$1))
endef

define get_goarch
$(word 4, $(subst _, ,$1))
endef

define get_goarm
$(word 5, $(subst _, ,$1))
endef

#### Rules Section ####

# builds main executable
.PHONY: all
all: $(app_name)

# builds main executable
$(prefix)/$(app_name): $(go_deps)
	go build $(flags) -o $(@)

# build main executable
.PHONY: $(app_name)
$(app_name): $(prefix)/$(app_name)

# installs main executable in user's default bin for golang
.PHONY: install
install:
	go install $(flags)

# cross compiles binaries for linux and darwin
$(objects): $(go_deps)
	$(eval goos=$(call get_goos, $(@)))
	$(eval goarch=$(call get_goarch, $(@)))
	$(eval goarm=$(call get_goarm, $(@)))
	GOOS=$(goos) GOARCH=$(goarch) GOARM=$(goarm) go build $(flags) -o $(@)

# creates zips of pre-built binaries
$(zips): $(objects)
	zip -j $(@) $(@:.zip=)

# generates a relase of all pre-built binaries
.PHONY: release
release: $(zips)

# run tests
.PHONY: test
test:
	go test -v -race ./...

# generate mocks
.PHONY: mock
mock:
	go generate ./...

# remove buid directory and installed executable
.PHONY: clean
clean:
	rm -f $(GOPATH)/bin/$(app_name)
	rm -rf $(prefix)
