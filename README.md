# Generate DNS Zone Files from Netbox

[![License](https://img.shields.io/github/license/michaelkoetter/netbox-dns-zone)](#)
[![Latest Release](https://img.shields.io/github/v/tag/michaelkoetter/netbox-dns-zone?label=release&sort=semver)](#)
[![Build Docker Image](https://github.com/michaelkoetter/netbox-dns-zone/actions/workflows/build-image.yml/badge.svg)](https://github.com/michaelkoetter/netbox-dns-zone/actions/workflows/build-image.yml)
[![Docker Hub](https://img.shields.io/static/v1?logo=docker&label=Docker+Hub&message=mkoetter/netbox-dns-zone&color=informational)](https://hub.docker.com/r/mkoetter/netbox-dns-zone)

This script generates DNS forward and reverse zones from Netbox IP Addresses.

> WIP

## Docker Images

Docker Images are automatically built for AMD64 and ARM architectures and published on Docker Hub.

```bash
# "latest" tag is automatically updated for latest release
docker run --rm mkoetter/netbox-dns-zone:latest --help

# "edge" tag is automtically updated for each change in master
docker run --rm mkoetter/netbox-dns-zone:edge --help
```

## Development

```bash
python3 -m venv venv/
source venv/bin/activate
pip3 install -r requirements.txt
```

## Examples

### Generate a forward zone

```bash
python3 dns-zone.py generate --zone=example.com --parent-prefix=10.0.0.0/24 --nameserver=hadron --nameserver=axion
```

Result (example):
```bind
;; Do not edit manually!
;; This file was generated by netbox-dns-zone at: 2022-09-21T13:06:36

$ORIGIN example.com.
$TTL 3600
@                                       IN  SOA     hadron root 1663758395 86400 7200 3600000 3600
@                                       IN  TXT     "generated-by=netbox-dns-zone"
@                                       IN  TXT     "generated-at=2022-09-21T13:06:36"
@                                       IN  NS      hadron
@                                       IN  NS      axion
precious-pony                           IN  A       10.0.0.10
artistic-buffalo                        IN  A       10.0.0.11
wealthy-pipefish                        IN  A       10.0.0.12
```

### Generate a reverse zone

```bash
python3 dns-zone.py generate --zone=example.com --reverse-prefix=10.0.0.0/24 --nameserver=hadron --nameserver=axion
```

Result (example):
```bind
;; Do not edit manually!
;; This file was generated by netbox-dns-zone at: 2022-09-21T13:07:29

$ORIGIN 0.0.10.in-addr.arpa.
$TTL 3600
@                                       IN  SOA     hadron.example.com. root.example.com. 1663758448 86400 7200 3600000 3600
@                                       IN  TXT     "generated-by=netbox-dns-zone"
@                                       IN  TXT     "generated-at=2022-09-21T13:07:29"
@                                       IN  NS      hadron.example.com.
@                                       IN  NS      axion.example.com.
10                                      IN  PTR     precious-pony.example.com.
11                                      IN  PTR     artistic-buffalo.example.com.
12                                      IN  PTR     wealthy-pipefish.example.com.
```