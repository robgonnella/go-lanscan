# go-lanscan
![Coverage](https://img.shields.io/badge/Coverage-91.6%25-brightgreen)

A network cli and golang package that allows you to perform arp and syn
scanning on a local area network.

## Cli Usage

### Prerequisites

First you must install the following dependencies

- [golang]
- [libpcap]
  - mac - `brew install libpcap`
  - linux/debian - `sudo apt update && sudo apt install -y libpcap-dev`

### Installation

Once dependencies are installed, run the following command to install go-lanscan

```bash
go install github.com/robgonnella/go-lanscan@latest
```

### Pre-built Binaries

Some pre-built binaries are provided in the releases section of github:
https://github.com/robgonnella/go-lanscan/releases. These binaries still have
a prerequisite on libpcap being installed first.

### Docker

A docker image is provided with go-lanscan prebuilt.
https://hub.docker.com/r/rgonnella/go-lanscan

See [docker-compose.yml](./docker-compose.yml) for an example setup.

**Linux**

```bash
docker run --rm --network host -v $(pwd)/reports:/reports rgonnella/go-lanscan:latest
```

**MacOS**

On MacOS, host network does not work so you will only be able to scan whatever
docker network the container is in. See
[docker-compose.yml](./docker-compose.yml) for an example.

```bash
docker run --rm -v $(pwd)/reports:/reports rgonnella/go-lanscan:latest
```

### Usage

```bash
# print usage info for this cli
go-lanscan --help

# scan all ports on current LAN
sudo go-lanscan

# scan specific ports
sudo go-lanscan --ports 22,111,3000-9000

# scan specific targets   single ip          ip range          cidr
sudo go-lanscan --targets 192.22.22.1,192.168.1.1-192.168.1.50,192.56.42.1/24

# include vendor look-ups on mac addresses (scan will be a little slower)
sudo go-lanscan --vendor

# include reverse dns lookup for hostnames
sudo go-lanscan --hostnames

# update static database used for vendor lookups
# static file is located at ~/.config/go-lanscan/oui.txt
sudo go-lanscan update-vendors

# choose specific interface when scanning
sudo go-lanscan --interface en0

# only output final result as table text
sudo go-lanscan --no-progress

# only output final result in json
sudo go-lanscan --no-progress --json

# run only arp scanning (skip syn scanning)
sudo go-lanscan --arp-only

# set timing - this is how fast packets are sent to hosts
# default is 100µs between packets
# the faster you send packets (shorter the timing), the less accurate the results will be
sudo go-lanscan --timing 1ms # set to 1 millisecond
sudo go-lanscan --timing 500µs # set to 500 microseconds
sudo go-lanscan --timing 500us # alternate symbol for microseconds
```

## Package Usage

### Prerequisites

First you must install the following dependencies

- [libpcap]
  - mac - `brew install libpcap`
  - linux/debian - `sudo apt update && sudo apt install -y libpcap-dev`

### Example Usage

- [arp-scanner](./examples/arp/arpscan.go)
- [syn-scanner](./examples/syn/synscan.go)
- [full-scanner](./examples/full/fullscan.go)

### Package Options

You can provide the following options to all scanners

- Provide specific timing duration

This option is used to set a specific time to wait between sending packets
to hosts. The default is 100µs. The shorter the timing, the faster packets
will be sent, and the less accurate your results will be

```go
  timing := time.Microsecond * 200

  fullScanner := scanner.NewFullScanner(
		netInfo,
		targets,
		ports,
		listenPort,
		scanner.WithTiming(timing),
  )

  // or
  fullScanner.SetTiming(timing)

  // or
  option := scanner.WithTiming(timing)
  option(fullScanner)
```

- Provide channel for notifications when packet requests are sent to target

```go
  requests := make(chan *scanner.Request)

  synScanner := scanner.NewSynScanner(
    targets,
    netInfo,
    ports,
    listenPort,
    synResults,
    synDone,
    scanner.WithRequestNotifications(requests),
  )

  // or
  synScanner.SetRequestNotifications(requests)

  // or
  option := scanner.WithRequestNotifications(requests)
  option(synScanner)
```

- Provide your own idle timeout. If no packets are received from our targets
  for this duration, a timeout occurs and the scanner is marked done

```go
  arpScanner := scanner.NewArpScanner(
    targets,
    netInfo,
    arpResults,
    arpDone,
    scanner.WithIdleTimeout(time.Second*10)
  )

  // or
  arpScanner.SetIdleTimeout(time.Second*10)

  // or
  option := scanner.WithIdleTimeout(time.Second*10)
  option(arpScanner)
```

- The next option performs vendor look-ups for mac addresses and can only be
applied to arpScanner and fullScanner. Vendor lookup is performed by downloading
a static database from https://standards-oui.ieee.org/oui/oui.txt and performing
queries against this file. The file is stored at `~/.config/go-lanscan/oui.txt`

```go
  import (
    ...
    "github.com/robgonnella/go-lanscan/pkg/oui"
  )

  vendorRepo, err := oui.GetDefaultVendorRepo()

  if err != nil {
    panic(err)
  }

  arpScanner := scanner.NewArpScanner(
    targets,
    netInfo,
    arpResults,
    arpDone,
    scanner.WithVendorInfo(vendorRepo)
  )

  // or
  arpScanner.IncludeVendorInfo(vendorRepo)

  // or
  option := scanner.WithVendorInfo(vendorRepo)
  option(arpScanner)
```

- Perform reverse dns lookup to find hostnames for found devices

```go
  arpScanner := scanner.NewArpScanner(
    targets,
    netInfo,
    arpResults,
    arpDone,
    scanner.WithHostnames(true)
  )

  // or
  arpScanner.IncludeHostnames(true)

  // or
  option := scanner.WithHostnames(true)
  option(arpScanner)
```

[golang]:  https://go.dev/doc/install
[libpcap]: https://github.com/the-tcpdump-group/libpcap
