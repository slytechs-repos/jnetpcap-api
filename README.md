# jNetPcap API
A full featured, protocol enabled, java API with IP Fragment tracking and reassembly.

## About

**jNetPcap API** is a Java library that provides access to libpcap, a low-level network monitoring library. The library allows Java developers to write applications that can capture, read, and manipulate network packets in real-time.

To use **jNetPcap API**, you need to download and install the library and add it to your Java project's classpath. Once you have done that, you can use the Java API provided by jNetPcap* to interact with network packets.

The library includes a set of classes and methods that allow you to capture network packets, filter and search through them, extract and analyze packet data, and ultimately write custom network analysis applications.

To begin capturing packets, you can create an instance of the `Pcap` class, which represents a network interface that the library will use to capture packets. Then you can create a `PcapPacketHandler` instance to process each packet as it is captured.

**jNetPcap API** also includes functionality for creating filters to capture only the packets that match certain criteria, such as a specific port, protocol, or IP address. Additionally, the library supports packet decoding and analysis for a variety of common protocols, including TCP, UDP, and ICMP wtih IP fragment reassembly if desired.

> **Note!** TCP stream reassebly is provided by **jNetWorks SDK** (Available soon!) library which is a more advanced network capture and analsysis SDK, and currently not available with **jNetPcap API**.

## How to use this library
The **jNetPcap API** library provides the starting point for your application. 

### Setup
The library requires [**jnetpcap-wrapper**][jnetpcap-wrapper], a low level *libpcap* module and the [**protocol-pack-sdk**][protocol-pack-sdk] modules which provide runtime and protocol support to **jNetPcap API**, grouped in numerous protocol packs.

#### Maven Central setup
```
<dependency>
	<groupId>com.slytechs.jnet.jnetpcap</groupId>
	<artifactId>jnetpcap-api</artifactId>
	<version>0.10.0</version>
</dependency>
```

## Examples
To get started lets take a look at a couple of examples.

Capturing packets with full protocol header access is easy.
```java
void main() throws PcapException {
	/* Pcap capture file to read */
	final String PCAP_FILE = "pcaps/HTTP.cap";
	
	/*
	 * Automatically close Pcap resource when done and checks the client and
	 * installed runtime API versions to ensure they are compatible.
	 */
	try (NetPcap pcap = NetPcap.openOffline(PCAP_FILE)) {

		/* Set a pretty print formatter to toString() method */
		pcap.setPacketFormatter(new PacketFormat());

		/* Number of packets to capture */
		final int PACKET_COUNT = 10;

		/* API API! Create protocol headers and reuse inside the dispatch handler */
		final Ethernet ethernet = new Ethernet();
		final Ip4 ip4 = new Ip4();
		final Tcp tcp = new Tcp();
		final Ip4RouterOption router = new Ip4RouterOption();

		/* Capture packets and access protocol headers */
		pcap.dispatch(PACKET_COUNT, (String user, Packet packet) -> { // API API

			// If present, printout ethernet header
			if (packet.hasHeader(ethernet))
				System.out.println(ethernet);
			
			// If present, printout ip4 header
			if (packet.hasHeader(ip4))
				System.out.println(ip4);

			// If present, printout IPv4.router header extension
			if (packet.hasHeader(ip4) && ip4.hasExtension(router))
				System.out.println(router);

			// If present, printout tcp header
			if (packet.hasHeader(tcp))
				System.out.println(tcp);

		}, "Example - Hello World");
	}
}
```
Here is a sample of all the IPF options and how to setup. The dispatched `Ip4` containing packets will have IPv4 datagrams fully reassembled, and optionally you can supress individual IP fragments, tracking and many other IPF related options.:
```java
/* Enable IP fragmentation reassembly and use many IPF options */
pcap
		.enableIpf(true) // Enables both IPF reassembly and tracking
		.enableIpfReassembly(true) // Default, but this is how you disable
		.enableIpfTracking(true) // Default, but this is how you disable
		.enableIpfAttachComplete(true) // Attach only complete dgrams to last IPF
		.enableIpfAttachIncomplete(true) // Attach incomplete dgrams as well to last IPF
		.enableIpfPassthroughFragments(true) // Pass through original IP fragments
		.enableIpfPassthroughComplete(true) // Pass through new reassembled dgrams
		.enableIpfPassthroughIncomplete(true) // Pass through new incomplete dgrams
		.setIpfTimeoutOnLast(false) // Otherwise only timeout on duration
		.setIpfBufferSize(1, MemoryUnit.MEGABYTES) // Total reassembly buffer size
		.setIpfTableSize(16, CountUnit.KILO) // How many hash table entries
		.setIpfMaxFragmentCount(16) // Max number of IP fragments per hash entry
		.setIpfTimeoutMilli(1200) // Timeout in system or packet time for incomplete dgrams
		.setIpfMaxDgramSize(64, MemoryUnit.KILOBYTES) // Max reassembled IP dgram size
		.useIpfPacketTimesource() // Or System timesource
		.activateIpf(); // Or Pcap.activate() if using Pcap.create(...)
```

[protocol-pack-sdk]: https://github.com/slytechs-repos/protocol-pack-sdk
[jnetpcap-wrapper]: https://github.com/slytechs-repos/jnetpcap-wrapper
[jnetpcap-examples]: https://github.com/slytechs-repos/jnetpcap-examples
[jnetworks]: https://github.com/slytechs-repos/jnetworks-sdk
