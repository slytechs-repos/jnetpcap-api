# jNetPcap API

[![Java](https://img.shields.io/badge/Java-22%2B-orange.svg)](https://openjdk.java.net/projects/jdk/22/) [![Maven Central](https://img.shields.io/badge/Maven-Central-blue.svg)](https://search.maven.org/artifact/com.slytechs.sdk/jnetpcap-api) [![License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://claude.ai/chat/LICENSE)

High-level packet capture and protocol analysis API for the jNetPcap SDK.

**jnetpcap-api** extends the low-level libpcap bindings with protocol dissection, IP fragment reassembly, TCP stream reconstruction, and zero-allocation packet processing.

------

## Table of Contents

1. [Quick Start](https://claude.ai/chat/7bb340ad-df75-49f3-8a46-20bf36a9141c#quick-start)
2. [License Activation](https://claude.ai/chat/7bb340ad-df75-49f3-8a46-20bf36a9141c#license-activation)
3. [Features](https://claude.ai/chat/7bb340ad-df75-49f3-8a46-20bf36a9141c#features)
4. [Examples](https://claude.ai/chat/7bb340ad-df75-49f3-8a46-20bf36a9141c#examples)
5. [Architecture](https://claude.ai/chat/7bb340ad-df75-49f3-8a46-20bf36a9141c#architecture)
6. [Advanced Installation](https://claude.ai/chat/7bb340ad-df75-49f3-8a46-20bf36a9141c#advanced-installation)
7. [Documentation](https://claude.ai/chat/7bb340ad-df75-49f3-8a46-20bf36a9141c#documentation)

------

## Quick Start

### Installation

Add a single dependency:

```xml
<dependency>
    <groupId>com.slytechs.sdk</groupId>
    <artifactId>jnetpcap-sdk</artifactId>
    <version>3.0.0</version>
</dependency>
```

That's it. All dependencies (bindings, protocols, etc.) are pulled transitively.

### Hello World

```java
import com.slytechs.sdk.jnetpcap.api.NetPcap;

public class HelloCapture {
    public static void main(String[] args) throws PcapException {
        // Activate community license (required, internet connection needed)
        NetPcap.activateLicense();
        
        try (var pcap = NetPcap.openOffline("capture.pcap")) {
            
            pcap.dispatch(10, packet -> {
                System.out.println(packet);
            });
        }
    }
}
```

### JVM Arguments

jNetPcap uses Java's Foreign Function & Memory (FFM) API. Add these JVM arguments:

```bash
java --enable-native-access=com.slytechs.sdk.jnetpcap,com.slytechs.sdk.common -jar myapp.jar
```

------

## License Activation

The jNetPcap SDK includes a **free unlimited Community Edition license**.

```java
public static void main(String[] args) throws PcapException {
    // Required: Call once at application startup
    NetPcap.activateLicense();
    
    // Now use jNetPcap normally
    try (var pcap = NetPcap.openOffline("capture.pcap")) {
        pcap.loop(-1, packet -> System.out.println(packet));
    }
}
```

**Requirements:**

- Call `NetPcap.activateLicense()` before any capture operations
- Internet connectivity required for activation
- No registration or API keys needed

The Community Edition is licensed under Apache 2.0 with telemetry. For commercial licenses without telemetry, contact [sales@slytechs.com](mailto:sales@slytechs.com).

------

## Features

- **Protocol Dissection** - Automatic parsing of L2-L7 protocols
- **IP Fragment Reassembly** - Reconstruct fragmented datagrams
- **TCP Stream Reconstruction** - Reassemble TCP segments in order
- **Zero-Allocation Processing** - Reusable headers for 100M+ pps
- **Multiple Protocol Packs** - TCP/IP, Web, Infrastructure

------

## Examples

### Zero-Allocation Header Access

Headers are designed for reuse - allocate once, bind many times:

```java
import com.slytechs.sdk.jnetpcap.api.NetPcap;
import com.slytechs.sdk.protocol.tcpip.ip.Ip4;
import com.slytechs.sdk.protocol.tcpip.tcp.Tcp;

public class ZeroAllocationExample {
    public static void main(String[] args) throws PcapException {
        NetPcap.activateLicense();
        
        // Allocate headers ONCE outside hot path
        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();
        
        try (var pcap = NetPcap.openOffline("capture.pcap")) {
            
            pcap.dispatch(-1, packet -> {
                
                // hasHeader() checks presence AND binds header to packet data
                if (packet.hasHeader(ip4)) {
                    System.out.printf("IP: %s -> %s%n", ip4.src(), ip4.dst());
                }
                
                if (packet.hasHeader(tcp)) {
                    System.out.printf("TCP: %d -> %d [SYN=%b ACK=%b]%n", 
                        tcp.srcPort(), tcp.dstPort(), tcp.isSyn(), tcp.isAck());
                }
            });
        }
    }
}
```

### Live Capture with Filter

```java
public class LiveCaptureExample {
    public static void main(String[] args) throws PcapException {
        NetPcap.activateLicense();
        
        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();
        
        try (var pcap = NetPcap.create("eth0")) {
            pcap.setSnaplen(65535)
                .setPromisc(true)
                .setTimeout(Duration.ofSeconds(1))
                .activate();
            
            pcap.setFilter("tcp port 443");
            
            pcap.dispatch(1000, packet -> {
                if (packet.hasHeader(ip4) && packet.hasHeader(tcp)) {
                    System.out.printf("%s:%d -> %s:%d%n",
                        ip4.src(), tcp.srcPort(),
                        ip4.dst(), tcp.dstPort());
                }
            });
        }
    }
}
```

### Packet Persistence

Packets in callbacks are only valid during the callback. To keep them longer:

```java
Queue<Packet> queue = new ConcurrentLinkedQueue<>();

pcap.loop(-1, packet -> {
    if (packet.hasHeader(tcp) && tcp.isSyn()) {
        // persist() copies packet to independent memory
        Packet keeper = packet.persist();
        queue.add(keeper);
    }
});

// Process outside callback
Packet p;
while ((p = queue.poll()) != null) {
    // Process...
    p.recycle();  // Return to pool when done
}
```

### Tunnel Detection (Depth Parameter)

For tunneled protocols like IP-in-IP or Q-in-Q:

```java
Ip4 outerIp = new Ip4();
Ip4 innerIp = new Ip4();

pcap.dispatch(count, packet -> {
    
    // Depth 0 = outermost, Depth 1 = first tunnel
    if (packet.hasHeader(outerIp, 0) && packet.hasHeader(innerIp, 1)) {
        System.out.printf("Tunnel: %s -> %s encapsulates %s -> %s%n",
            outerIp.src(), outerIp.dst(),
            innerIp.src(), innerIp.dst());
    }
});
```

### TCP Options

```java
Tcp tcp = new Tcp();
TcpOptions options = new TcpOptions();

pcap.dispatch(count, packet -> {
    
    if (packet.hasHeader(tcp) && tcp.hasOptions()) {
        options.bind(tcp);
        
        if (options.hasMss())
            System.out.println("MSS: " + options.mss());
        if (options.hasWindowScale())
            System.out.println("WScale: " + options.windowScale());
        if (options.hasTimestamps())
            System.out.printf("TS: val=%d, ecr=%d%n", 
                options.tsVal(), options.tsEcr());
    }
});
```

### Packet Descriptor

```java
pcap.dispatch(10, packet -> {
    var desc = packet.descriptor();
    System.out.printf("Frame: caplen=%d wirelen=%d timestamp=%s%n",
        packet.captureLength(),
        packet.wireLength(),
        packet.timestampInfo());
});
```

------

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Application                        │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                      jnetpcap-api                           │
│           (NetPcap, Packet, Protocol Dissection)            │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ sdk-protocol  │   │ sdk-protocol  │   │ sdk-protocol  │
│    -tcpip     │   │     -web      │   │    -infra     │
└───────────────┘   └───────────────┘   └───────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                   jnetpcap-bindings                         │
│              (Panama FFM bindings to libpcap)               │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                  Native libpcap / Npcap                     │
└─────────────────────────────────────────────────────────────┘
```

------

## Advanced Installation

### Cherry-Pick Modules (With BOM)

For fine-grained control over which modules to include:

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
    <!-- Pick only what you need - versions managed by BOM -->
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
    implementation 'com.slytechs.sdk:jnetpcap-sdk:3.0.0'
}
```

### Module Declaration

```java
module your.app {
    requires com.slytechs.sdk.jnetpcap.api;
}
```

------

## Native Library Requirements

| Platform | Library | Installation                    |
| -------- | ------- | ------------------------------- |
| Linux    | libpcap | `apt install libpcap-dev`       |
| macOS    | libpcap | Pre-installed                   |
| Windows  | Npcap   | [npcap.com](https://npcap.com/) |

------

## Documentation

- [jnetpcap-examples](https://github.com/slytechs-repos/jnetpcap-examples) - Working examples
- [GitHub Wiki](https://github.com/slytechs-repos/jnetpcap-api/wiki) - User guides and tutorials
- [Javadocs](https://slytechs-repos.github.io/jnetpcap-api/) - API documentation

------

## Related Projects

| Module                                                       | Description                        |
| ------------------------------------------------------------ | ---------------------------------- |
| [jnetpcap-sdk](https://github.com/slytechs-repos/jnetpcap-sdk) | Starter - pulls all dependencies   |
| [jnetpcap-bindings](https://github.com/slytechs-repos/jnetpcap-bindings) | Low-level libpcap bindings         |
| [sdk-protocol-tcpip](https://github.com/slytechs-repos/sdk-protocol-tcpip) | TCP/IP protocol pack               |
| [sdk-protocol-web](https://github.com/slytechs-repos/sdk-protocol-web) | Web protocol pack (HTTP, TLS, DNS) |

------

## License

Licensed under Apache License v2.0. See [LICENSE](https://claude.ai/chat/LICENSE) for details.

------

**Sly Technologies Inc.** - High-performance network analysis solutions

Website: [www.slytechs.com](https://www.slytechs.com/)
