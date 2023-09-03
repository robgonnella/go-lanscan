# go-lanscan

A network cli and golang package that allows you to perform arp and syn
scanning on a local area network.

## Installation

First install [golang], then run the following command.

go install github.com/robgonnella/go-lanscan@latest

## Cli Usage

```bash
# print usage info for this cli
lanscan --help

# scan all ports on current LAN
lanscan

# scan specific ports
lanscan --ports 22,111,3000-9000

# scan specific targets
lanscan --targets 192.22.22.1,192.56.42.1/24

# choose specific interface when scanning
lanscan --interface en0

# only output final result as table text
lanscan --no-progress

# only output final result in json
lanscan --no-progress --json
```

## Package Usage

- [arp-scanner](./examples/arpscan.go)
- [syn-scanner](./examples/synscan.go)

For both ArpScanner and SynScanner you can optionally receive a callback
whenever a packet is sent to a target

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
    scanner.WithSynIdleTimeout(time.Second*time.Duration(idleTimeout)),
  )
```

You can also choose to set options via setter methods

```go
  callback := func(request *scanner.Request) {
    fmt.Printf("arp packet sent to %s on port %s", request.IP, request.Port)
  }

  arpScanner, err := scanner.NewArpScanner(
    targets,
    netInfo,
    arpResults,
    arpDone,
  )

  if err != nil {
    panic(err)
  }

  arpScanner.SetRequestNotifications(callback)
  arpScanner.SetIdleTimeout(time.Second*time.Duration(idleTimeout))
```

[golang]:  https://go.dev/doc/install
