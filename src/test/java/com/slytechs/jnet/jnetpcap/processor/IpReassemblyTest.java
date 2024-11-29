package com.slytechs.jnet.jnetpcap.processor;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.jnetruntime.util.Registration;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.network.Ip;
import com.slytechs.jnet.protocol.core.network.IpReassembly;
import com.slytechs.jnet.protocol.core.network.IpReassemblyConfig;
import com.slytechs.jnet.protocol.core.network.ReassemblyEventListener;
import com.slytechs.jnet.protocol.descriptor.Type2Descriptor;

/**
 * Test program demonstrating IP datagram reassembly from PCAP capture file
 * using JNetPcap.
 */
public class IpReassemblyTest implements ReassemblyEventListener, AutoCloseable {

	private final IpReassembly reassembly;
	private final Registration registration;
	private final Packet packet;
	private final Ip ip;
	private long packetCount = 0;
	private long fragmentCount = 0;

	/**
	 * Packet handler for processing packets from PCAP
	 */
	private final OfPacket<String> packetHandler = new OfPacket<String>() {
		@Override
		public void handlePacket(String ctx, Packet packet) {
			packetCount++;

			if (packet.hasHeader(ip)) {
				if (reassembly.hasFragments(packet)) {
					fragmentCount++;
					reassembly.processFragment(packet);
				}
			}
		}
	};

	public IpReassemblyTest() {
		// Configure reassembly using setters
		IpReassemblyConfig config = new IpReassemblyConfig();
		config.setMaxTableSize(1024);
		config.setMaxSegmentsPerDgram(256);
		config.setReassemblyTimeoutNanos(TimeUnit.SECONDS.toNanos(30));
		config.setMaxDatagramSize(65535);

		this.reassembly = new IpReassembly(config);
		this.registration = reassembly.addEventListener(this);

		// Initialize packet processing
		this.packet = new Packet(new Type2Descriptor());
		this.ip = new Ip();
	}

	@Override
	public void onEvent(ReassemblyEvent event) {
		System.out.printf("%n=== Reassembly Event ===%n");
		System.out.println(event.toString());

		if (event.getType() == ReassemblyContext.FragmentEventType.COMPLETE) {
			System.out.printf("%n=== Reassembly Complete ===%n");
			System.out.println("Fragment Report:");
			System.out.println(event.getFragmentReport());
			System.out.println("Timing Report:");
			System.out.println(event.getTimingReport());
		}
	}

	private void printStats() {
		System.out.printf("%n=== Processing Statistics ===%n");
		System.out.printf("Total Packets: %d%n", packetCount);
		System.out.printf("Total Fragments: %d%n", fragmentCount);
		System.out.printf("%n=== Reassembly Statistics ===%n");
		System.out.println(reassembly.getStats().toString());
	}

	/**
	 * Process a PCAP file
	 */
	public void processPcapFile(String pcapFile) throws IOException {
		try (NetPcap pcap = NetPcap.offline(pcapFile)) {
			System.out.printf("Processing PCAP file: %s%n", pcapFile);

			// Create packet handler for dispatch
			OfPacket<String> handler = (ctx, pkt) -> {
				packet.bind(pkt.buffer());
				return packetHandler.onPacket(ctx, packet);
			};

			// Dispatch packets to our handler
			int count = pcap.dispatchPacket(0, handler, null);

			System.out.printf("%nProcessed %d packets%n", count);
		}
	}

	@Override
	public void close() {
		registration.unregister();
		reassembly.shutdown();
	}

	public static void main(String[] args) {
		if (args.length != 1) {
			System.err.println("Usage: IpReassemblyTest <pcap-file>");
			System.exit(1);
		}

		String pcapFile = args[0];

		try (IpReassemblyTest test = new IpReassemblyTest()) {
			test.processPcapFile(pcapFile);
			test.printStats();

		} catch (IOException e) {
			System.err.printf("Error processing PCAP file: %s%n", e.getMessage());
			e.printStackTrace();
		}
	}
}