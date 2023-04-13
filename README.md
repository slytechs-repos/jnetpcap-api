# jNetPcap Pro
A protocol enabled **jNetPcap** library with IP Fragment tracking and reassembly.

## How to use this library
The **jNetPcap Pro** library provides starting point for your application. 

### Prerequisites
The library requires [**jnetpcap v2**][jnetpcap] open-source module and the [**core-protocols**][core-protocols] module which provides runtime and protocol support to **jNetPcap Pro**.

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
	try (PcapPro pcap = PcapPro.openOffline(PCAP_FILE)) { // Pro API

		/* Set a pretty print formatter to toString() method */
		pcap.setPacketFormatter(new PacketFormat());

		/* Number of packets to capture */
		final int PACKET_COUNT = 10;

		/* Pro API! Create protocol headers and reuse inside the dispatch handler */
		final Ethernet ethernet = new Ethernet();
		final Ip4 ip4 = new Ip4();
		final Tcp tcp = new Tcp();
		final Ip4RouterOption router = new Ip4RouterOption();

		/* Capture packets and access protocol headers */
		pcap.dispatch(PACKET_COUNT, (String user, Packet packet) -> { // Pro API

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

[core-protocols]: https://github.com/slytechs-repos/core-protocols
[jnetpcap]: https://github.com/slytechs-repos/jnetpcap
[jnetpcap-examples]: https://github.com/slytechs-repos/jnetpcap-examples
