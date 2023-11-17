# go-lanscan
![Coverage](https://img.shields.io/badge/Coverage-90.7%25-brightgreen)

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

# set accuracy to low, which results in a faster scan but may
# miss some open ports
sudo go-lanscan --accuracy low
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

- Provide callback for notifications when packet requests are sent to target

```go
  callback := func(request *scanner.Request) {
    fmt.Printf("syn packet sent to %s on port %s", request.IP, request.Port)
  }

  synScanner := scanner.NewSynScanner(
    targets,
    netInfo,
    ports,
    listenPort,
    synResults,
    synDone,
    scanner.WithRequestNotifications(callback),
  )

  // or
  option := scanner.WithRequestNotifications(callback)
  option(synScanner)

  // or
  synScanner.SetRequestNotifications(callback)
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
  arpScanner := scanner.NewArpScanner(
    targets,
    netInfo,
    arpResults,
    arpDone,
    scanner.WithVendorInfo(true)
  )

  // or
  arpScanner.IncludeVendorInfo(true)

  // or
  option := scanner.WithVendorInfo(true)
  option(arpScanner)
```

- Set accuracy of scanning (LOW, MEDIUM, HIGH). Low results in a faster scan
  but may miss some open ports. The default is HIGH. This option can be set
  on any scanner

```go
  synScanner := scanner.NewSynScanner(
    targets,
    netInfo,
    ports,
    listenPort,
    synResults,
    synDone,
    scanner.WithAccuracy(scanner.LOW_ACCURACY),
  )

  // or
  synScanner.SetAccuracy(scanner.LOW_ACCURACY)

  // or
  option := scanner.WithAccuracy(scanner.LOW_ACCURACY)
  option(synScanner)
```


[golang]:  https://go.dev/doc/install
[libpcap]: https://github.com/the-tcpdump-group/libpcap
