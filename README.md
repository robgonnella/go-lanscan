# go-lanscan

A network cli and golang package that allows you to perform arp and syn
scanning on a local area network.

## Cli Usage

### Installation

First install [golang], then run the following command.

```bash
go install github.com/robgonnella/go-lanscan@latest
```

### Usage

```bash
# print usage info for this cli
go-lanscan --help

# scan all ports on current LAN
sudo go-lanscan

# scan specific ports
sudo go-lanscan --ports 22,111,3000-9000

# scan specific targets
sudo go-lanscan --targets 192.22.22.1,192.56.42.1/24

# include vendor look-ups on mac addresses (scan will be a little slower)
sudo go-lanscan --vendor

# choose specific interface when scanning
sudo go-lanscan --interface en0

# only output final result as table text
sudo go-lanscan --no-progress

# only output final result in json
sudo go-lanscan --no-progress --json
```

## Package Usage

- [arp-scanner](./examples/arpscan.go)
- [syn-scanner](./examples/synscan.go)
- [full-scanner](./examples/fullscan.go)

### Package Options

You can provide the following options to all scanners

- Provide callback for notifications when packet requests are sent to target

```go
  callback := func(request *scanner.Request) {
    fmt.Printf("syn packet sent to %s on port %s", request.IP, request.Port)
  }

  synScanner, err := scanner.NewSynScanner(
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
  arpScanner, err := scanner.NewArpScanner(
    targets,
    netInfo,
    arpResults,
    arpDone,
    scanner.WithIdleTimeout(time.Second*10)
  )

  if err != nil {
    panic(err)
  }

  // or
  arpScanner.SetIdleTimeout(time.Second*10)

  // or
  option := scanner.WithIdleTimeout(time.Second*10)
  option(arpScanner)
```

The next option performs vendor look-ups for mac addresses and can only be
applied to arpScanner and fullScanner.

```go
  vendorResults := make(chan *scanner.VendorResult)

  arpScanner, err := scanner.NewArpScanner(
    targets,
    netInfo,
    arpResults,
    arpDone,
    scanner.WithVendorInfo(vendorResults)
  )

  if err != nil {
    panic(err)
  }

  // or
  option := scanner.WithVendorInfo(vendorResults)
  option(arpScanner)
```

[golang]:  https://go.dev/doc/install
