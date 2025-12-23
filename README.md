# jNetPcap API

[![Java](https://img.shields.io/badge/Java-22%2B-orange.svg)](https://openjdk.java.net/projects/jdk/22/) [![Panama FFM](https://img.shields.io/badge/Panama-Foreign%20Memory-blue.svg)](https://openjdk.java.net/projects/panama/) [![Maven Central](https://img.shields.io/badge/Maven-Central-blue.svg)](https://search.maven.org/artifact/com.slytechs.sdk/jnetpcap-api) [![License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://claude.ai/chat/LICENSE)

High-level packet capture and protocol analysis API for Java.

**jNetPcap API** extends [jnetpcap-bindings](https://github.com/slytechs-repos/jnetpcap-bindings) with protocol dissection, IP fragment reassembly, TCP stream reconstruction, and a powerful packet processing pipeline. This is **version 3** of the popular **jNetPcap** library.

------

## Table of Contents

1. [Overview](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#overview)
2. [Features](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#features)
3. [Architecture](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#architecture)
4. [Quick Start](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#quick-start)
5. [Examples](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#examples)
6. [Protocol Support](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#protocol-support)
7. [Installation](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#installation)
8. [Documentation](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#documentation)
9. [Related Projects](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#related-projects)

------

## Overview

jNetPcap API provides a complete packet capture and analysis solution:

- **Protocol Dissection** - Automatic parsing of network protocols (Ethernet, IP, TCP, UDP, etc.)
- **Fragment Reassembly** - IP datagram reassembly across fragments
- **Stream Reconstruction** - TCP stream tracking and payload reconstruction
- **Zero-Copy Processing** - High-performance packet handling via Panama FFM
- **Flexible Pipeline** - Configurable capture and analysis pipeline

------

## Features

### Packet Capture

- Live capture from network interfaces
- Offline analysis from PCAP/PCAPNG files
- BPF filter support
- Promiscuous and monitor modes

### Protocol Analysis

- Automatic protocol detection and dissection
- Header field access via type-safe Java objects
- Protocol-specific detail builders for formatted output
- Extensible protocol pack system

### Reassembly & Tracking

- IPv4/IPv6 fragment reassembly
- TCP stream reconstruction
- Connection tracking
- Flow analysis

### Performance

- Zero-allocation packet processing paths
- Memory-mapped file support
- Batch packet processing
- Lock-free data structures

### Zero-Allocation Header Access

Headers are designed for reuse in high-performance capture loops:

```java
// Allocate ONCE outside hot path
Ip4 ip4 = new Ip4();
Tcp tcp = new Tcp();

pcap.dispatch(count, packet -> {
    // hasHeader() checks presence AND binds header to packet data
    if (packet.hasHeader(ip4)) {
        // ip4 is now bound - access fields directly
        processIp(ip4.src(), ip4.dst());
    }
    
    if (packet.hasHeader(tcp)) {
        processTcp(tcp.srcPort(), tcp.dstPort());
    }
});
```

This pattern enables 100M+ pps processing with zero garbage collection pressure.

------

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Application                         │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                     jnetpcap-api                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   NetPcap   │  │   Packet    │  │   Reassembly &      │  │
│  │  (capture)  │  │  Pipeline   │  │   Stream Tracking   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                   Protocol Packs                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ sdk-protocol │  │ sdk-protocol │  │ sdk-protocol │       │
│  │    -tcpip    │  │     -web     │  │    -infra    │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│              jnetpcap-bindings (Panama FFM)                 │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                 libpcap / Npcap / WinPcap                   │
└─────────────────────────────────────────────────────────────┘
```

------

## Quick Start

### Using jnetpcap-sdk (Recommended)

The easiest way to get started - pulls all dependencies automatically:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.slytechs.sdk</groupId>
            <artifactId>sdk-bom</artifactId>
            <version>3.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>com.slytechs.sdk</groupId>
        <artifactId>jnetpcap-sdk</artifactId>
    </dependency>
</dependencies>
```

### Module Declaration

```java
module your.module {
    requires com.slytechs.jnet.jnetpcap.api;
}
```

------

## Examples

### Capture and Dissect Packets

```java
void main() throws PcapException {
    var devices = NetPcap.findAllDevs();
    
    // Allocate headers ONCE outside the hot path
    Ethernet ethernet = new Ethernet();
    Ip4 ip4 = new Ip4();
    Tcp tcp = new Tcp();
    
    try (var pcap = NetPcap.create(devices.getFirst())) {
        pcap.activate();
        
        pcap.dispatch(10, packet -> {
            
            // hasHeader() checks presence AND binds header to packet data
            if (packet.hasHeader(ethernet)) {
                System.out.printf("Ethernet: %s -> %s%n", 
                    ethernet.src(), ethernet.dst());
            }
            
            if (packet.hasHeader(ip4)) {
                System.out.printf("IPv4: %s -> %s (proto=%d)%n",
                    ip4.src(), ip4.dst(), ip4.protocol());
            }
            
            if (packet.hasHeader(tcp)) {
                System.out.printf("TCP: %d -> %d [%s]%n",
                    tcp.srcPort(), tcp.dstPort(), tcp.flags());
            }
        });
    }
}
```

### Read from PCAP File with Protocol Stack

```java
void main() throws PcapException {
    final String FILENAME = "pcaps/HTTP.cap";
    
    // Configure protocol stack
    ProtocolStack stack = ProtocolStack.packetDissectionOnly();
    
    stack.getPacketPolicy()
        .zeroCopy(); // Enable zero-copy packet policy
    
    // Or use memory pool for packet copies
    // stack.getPacketPolicy()
    //     .copyToMemoryPool(new PacketMemoryPoolSettings()
    //         .withSize(16, MemoryUnit.MEGABYTES));
    
    // Pre-allocate headers outside hot path
    Ethernet ethernet = new Ethernet();
    Ip4 ip4 = new Ip4();
    Tcp tcp = new Tcp();
    
    try (var pcap = NetPcap.openOffline(FILENAME, stack)) {
        
        pcap.dispatch(Pcap.LOOP_INFINITE, packet -> {
            
            // Print packet descriptor
            System.out.println(packet.getPacketDescriptor());
            
            // Access headers - hasHeader() binds if present
            if (packet.hasHeader(ip4)) {
                System.out.println("IPv4: " + ip4.src() + " → " + ip4.dst());
                System.out.println("Version: " + ip4.version());
                System.out.println("Protocol: " + ip4.protocol());
            }
            
            if (packet.hasHeader(ethernet)) {
                System.out.println(ethernet);
            }
            
            if (packet.hasHeader(tcp)) {
                System.out.println("TCP: " + tcp.srcPort() + " → " + tcp.dstPort());
            }
        });
    }
}
```

### Filter Traffic

```java
void main() throws PcapException {
    Ip4 ip4 = new Ip4();
    Tcp tcp = new Tcp();
    
    try (var pcap = NetPcap.create(NetPcap.findAllDevs().getFirst())) {
        pcap.activate();
        
        // Capture only TCP port 443 (HTTPS)
        pcap.setFilter("tcp port 443");
        
        pcap.dispatch(100, packet -> {
            if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
                System.out.printf("HTTPS: %s:%d -> %s:%d%n",
                    ip4.src(), tcp.srcPort(),
                    ip4.dst(), tcp.dstPort());
            }
        });
    }
}
```

### Tunnel Detection with Depth

```java
void main() throws PcapException {
    Ip4 outerIp = new Ip4();
    Ip4 innerIp = new Ip4();
    
    try (var pcap = NetPcap.openOffline("tunnel.pcap")) {
        
        pcap.dispatch(Pcap.LOOP_INFINITE, packet -> {
            
            // Check for IP-in-IP tunnel (outer IP at depth 0, inner at depth 1)
            if (packet.hasHeader(outerIp, 0) && packet.hasHeader(innerIp, 1)) {
                System.out.printf("Tunnel: %s -> %s (outer) / %s -> %s (inner)%n",
                    outerIp.src(), outerIp.dst(),
                    innerIp.src(), innerIp.dst());
            }
        });
    }
}
```

### Packet Descriptor Details

```java
void main() throws PcapException {
    try (var pcap = NetPcap.openOffline("capture.pcap")) {
        
        pcap.dispatch(1, packet -> {
            // Print full descriptor with protocol table
            System.out.println(packet.getPacketDescriptor());
            
            // Output:
            // Net Packet Descriptor: cap=74 wire=74 ts=1299012579821
            //   Protocol Bitmap = 0x00000015 (ETH IPv4 TCP)
            //   Protocol Count = 3
            //   Inline Protocol Table:
            //     Ethernet: offset=0 length=14
            //     IPv4: offset=14 length=20
            //     TCP: offset=34 length=40
        });
    }
}
```

### JVM Arguments

```bash
java --enable-native-access=com.slytechs.jnet.jnetpcap \
     -Djava.library.path=/usr/lib \
     -jar your-app.jar
```

------

## Protocol Support

Protocol support is provided via separate protocol pack modules:

| Module                                                       | Protocols                                             |
| ------------------------------------------------------------ | ----------------------------------------------------- |
| [sdk-protocol-tcpip](https://github.com/slytechs-repos/sdk-protocol-tcpip) | Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, VLAN, MPLS |
| [sdk-protocol-web](https://github.com/slytechs-repos/sdk-protocol-web) | HTTP, TLS, DNS, QUIC, WebSocket                       |
| [sdk-protocol-infra](https://github.com/slytechs-repos/sdk-protocol-infra) | BGP, OSPF, STP, VRRP, LACP, LLDP                      |

All protocol packs are included when using `jnetpcap-sdk`.

------

## Installation

### Option 1: jnetpcap-sdk (Recommended)

Includes all dependencies:

```xml
<dependency>
    <groupId>com.slytechs.sdk</groupId>
    <artifactId>jnetpcap-sdk</artifactId>
</dependency>
```

### Option 2: Individual Modules

```xml
<dependencies>
    <dependency>
        <groupId>com.slytechs.sdk</groupId>
        <artifactId>jnetpcap-api</artifactId>
    </dependency>
    <dependency>
        <groupId>com.slytechs.sdk</groupId>
        <artifactId>sdk-protocol-tcpip</artifactId>
    </dependency>
</dependencies>
```

### Gradle

```groovy
dependencies {
    implementation platform('com.slytechs.sdk:sdk-bom:3.0.0')
    implementation 'com.slytechs.sdk:jnetpcap-sdk'
}
```

### Native Library

Requires one of:

- [libpcap](https://www.tcpdump.org/) (Linux/macOS)
- [Npcap](https://npcap.com/) (Windows, recommended)
- [WinPcap](https://www.winpcap.org/) (Windows, legacy)

------

## Documentation

- [GitHub Wiki](https://github.com/slytechs-repos/jnetpcap-api/wiki) - User guides and tutorials
- [Javadocs](https://slytechs-repos.github.io/jnetpcap-api/) - API documentation
- [SDK BOM](https://github.com/slytechs-repos/sdk-bom) - Version management
- [Examples](https://github.com/slytechs-repos/jnetpcap-api/tree/main/examples) - Sample code

------

## Related Projects

| Module                                                       | Description                          |
| ------------------------------------------------------------ | ------------------------------------ |
| [jnetpcap-sdk](https://github.com/slytechs-repos/jnetpcap-sdk) | Complete SDK starter (recommended)   |
| [jnetpcap-bindings](https://github.com/slytechs-repos/jnetpcap-bindings) | Low-level libpcap bindings           |
| [sdk-protocol-tcpip](https://github.com/slytechs-repos/sdk-protocol-tcpip) | TCP/IP protocol pack                 |
| [sdk-protocol-web](https://github.com/slytechs-repos/sdk-protocol-web) | Web protocol pack                    |
| [sdk-protocol-infra](https://github.com/slytechs-repos/sdk-protocol-infra) | Infrastructure protocol pack         |
| [sdk-common](https://github.com/slytechs-repos/sdk-common)   | Core utilities and memory management |
| [jnetworks-sdk](https://github.com/slytechs-repos/jnetworks-sdk) | High-performance capture (100Gbps+)  |

------

## Requirements

- **Java 22+** - Required for Panama FFM
- **libpcap/Npcap** - Native packet capture library
- **Linux/Windows/macOS** - Cross-platform support

------

## Contact

- **Email:** sales@slytechs.com
- **Website:** [www.slytechs.com](https://www.slytechs.com/)

------

## License

Licensed under Apache License v2.0. See [LICENSE](https://claude.ai/chat/LICENSE) for details.

------

**Sly Technologies Inc.** - High-performance network analysis solutions

Website: [www.slytechs.com](https://www.slytechs.com/)

------
