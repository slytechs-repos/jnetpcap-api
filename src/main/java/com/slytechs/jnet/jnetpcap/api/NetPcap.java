package com.slytechs.jnet.jnetpcap.api;

import java.io.File;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapIf;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapTStampPrecision;

import com.slytechs.jnet.core.api.memory.MemoryUnit;
import com.slytechs.jnet.core.api.util.Named;
import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfPacketConsumer;
import com.slytechs.jnet.protocol.api.Packet;
import com.slytechs.jnet.protocol.api.stack.PacketMemoryPoolSettings;
import com.slytechs.jnet.protocol.api.stack.ProtocolStack;
import com.slytechs.jnet.protocol.tcpip.ethernet.Ethernet;
import com.slytechs.jnet.protocol.tcpip.ip.Ip4;

public final class NetPcap extends BaseNetPcap implements Named, AutoCloseable {

	public static NetPcap create(PcapIf device) throws PcapException {
		return create(device, ProtocolStack.packetDissectionOnly());
	}

	public static NetPcap create(PcapIf device, ProtocolStack stack) throws PcapException {
		return create(device.name(), stack);
	}

	public static NetPcap create(String device) throws PcapException {
		return create(device, ProtocolStack.packetDissectionOnly());
	}

	public static NetPcap create(String device, ProtocolStack stack) throws PcapException {
		Pcap pcap = Pcap.create(device);
		return new NetPcap(pcap, stack);
	}

	public static void main(String[] args) throws PcapException {
		final String FILENAME = "pcaps/HTTP.cap";

		ProtocolStack stack = ProtocolStack.packetDissectionOnly();

		stack.getPacketPolicy()
				.zeroCopy(); // Enable zero copy packet policy

		stack.getPacketPolicy()
				.copyToMemoryPool(new PacketMemoryPoolSettings()
						.withSize(16, MemoryUnit.MEGABYTES));

		Ethernet ethernet = new Ethernet();
		Ip4 ip4 = new Ip4();
		try (NetPcap pcap = NetPcap.openOffline(FILENAME, stack)) {

			pcap.dispatch(1, packet -> {

				System.out.println(packet.getPacketDescriptor().toString());

				System.out.println(packet);

				if (packet.hasHeader(ip4)) {
					System.out.println("IPv4: " + ip4.src() + " → " + ip4.dst());
					System.out.println("Version: " + ip4.version());
					System.out.println("Protocol: " + ip4.protocol());
				}

				if (packet.hasHeader(ethernet))
					System.out.println(ethernet);
			});
		}
	}

	// ════════════════════════════════════════════════════════════════
	// Dispatch/Loop - delegate to dispatcher
	// ════════════════════════════════════════════════════════════════

	public static NetPcap openDead(PcapDlt linktype, int snaplen) throws PcapException {
		return openDead(linktype, snaplen, ProtocolStack.packetDissectionOnly());
	}

	public static NetPcap openDead(PcapDlt linktype, int snaplen,
			ProtocolStack stack) throws PcapException {
		Pcap pcap = Pcap.openDead(linktype, snaplen);
		return new NetPcap(pcap, stack);
	}

	public static NetPcap openDeadWithTstampPrecision(PcapDlt linktype, int snaplen,
			PcapTStampPrecision precision) throws PcapException {
		return openDeadWithTstampPrecision(linktype, snaplen, precision,
				ProtocolStack.packetDissectionOnly());
	}

	public static NetPcap openDeadWithTstampPrecision(PcapDlt linktype, int snaplen,
			PcapTStampPrecision precision, ProtocolStack stack) throws PcapException {
		Pcap pcap = Pcap.openDeadWithTstampPrecision(linktype, snaplen, precision);
		return new NetPcap(pcap, stack);
	}

	// ════════════════════════════════════════════════════════════════
	// openOffline - File reading
	// ════════════════════════════════════════════════════════════════

	public static NetPcap openLive(PcapIf device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit) throws PcapException {
		return openLive(device, snaplen, promisc, timeout, unit,
				ProtocolStack.packetDissectionOnly());
	}

	public static NetPcap openLive(PcapIf device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit, ProtocolStack stack) throws PcapException {
		return openLive(device.name(), snaplen, promisc, timeout, unit, stack);
	}

	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			Duration timeout) throws PcapException {
		return openLive(device, snaplen, promisc, timeout,
				ProtocolStack.packetDissectionOnly());
	}

	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			Duration timeout, ProtocolStack stack) throws PcapException {
		return openLive(device, snaplen, promisc, timeout.toMillis(), TimeUnit.MILLISECONDS, stack);
	}

	// ════════════════════════════════════════════════════════════════
	// openLive - Live capture
	// ════════════════════════════════════════════════════════════════

	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit) throws PcapException {
		return openLive(device, snaplen, promisc, timeout, unit,
				ProtocolStack.packetDissectionOnly());
	}

	public static NetPcap openLive(String device, int snaplen, boolean promisc,
			long timeout, TimeUnit unit, ProtocolStack stack) throws PcapException {
		Pcap pcap = Pcap.openLive(device, snaplen, promisc, timeout, unit);
		return new NetPcap(pcap, stack);
	}

	public static NetPcap openOffline(File file) throws PcapException {
		return openOffline(file, ProtocolStack.packetDissectionOnly());
	}

	public static NetPcap openOffline(File file, ProtocolStack stack) throws PcapException {
		return openOffline(file.getAbsolutePath(), stack);
	}

	public static NetPcap openOffline(String fname) throws PcapException {
		return openOffline(fname, ProtocolStack.packetDissectionOnly());
	}

	public static NetPcap openOffline(String fname, ProtocolStack stack) throws PcapException {
		Pcap pcap = Pcap.openOffline(fname);
		return new NetPcap(pcap, stack);
	}

	// ════════════════════════════════════════════════════════════════
	// openDead - Filter compilation / dump writing
	// ════════════════════════════════════════════════════════════════

	private final ProtocolStack stack;

	private final NetPcapCapturePipeline dispatcher;

	private NetPcap(Pcap wrapper, ProtocolStack stack) {
		super(wrapper);
		this.stack = Objects.requireNonNull(stack, "stack");
		this.dispatcher = new NetPcapCapturePipeline(stack);

		// Configure dispatcher based on pcap handle state
		configureDispatcher();
	}

	private void configureDispatcher() {
		// Set timestamp unit based on pcap precision
		// Set L2 type based on datalink
//        dispatcher.setTimestampUnit(resolveTimestampUnit());
//        dispatcher.setL2FrameType(resolveL2FrameType());
	}

	// ════════════════════════════════════════════════════════════════
	// create - Two-stage pattern (create → configure → activate)
	// ════════════════════════════════════════════════════════════════

	public <U> int dispatch(int count, OfPacket<U> handler, U user) throws PcapException {
		return dispatcher.dispatch(pcapApi, count, handler, user);
	}

	public int dispatch(int count, OfPacketConsumer handler) throws PcapException {
		return dispatcher.dispatch(pcapApi, count, handler);
	}

	public ProtocolStack getProtocolStack() {
		return stack;
	}

	public <U> int loop(int count, OfPacket<U> handler, U user) {
		return dispatcher.loop(pcapApi, count, handler, user);
	}

	// ════════════════════════════════════════════════════════════════
	// Accessor
	// ════════════════════════════════════════════════════════════════

	public int loop(int count, OfPacketConsumer handler) {
		return dispatcher.loop(pcapApi, count, handler);
	}

	/**
	 * @see com.slytechs.jnet.core.api.util.Named#name()
	 */
	@Override
	public String name() {
		return super.getName();
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.api.BaseNetPcap#next()
	 */
	@Override
	public Packet next() throws PcapException {
		throw new UnsupportedOperationException("not implemented yet");
	}

	/**
	 * @see com.slytechs.jnet.jnetpcap.api.BaseNetPcap#nextEx()
	 */
	@Override
	public Packet nextEx() throws PcapException, TimeoutException {
		throw new UnsupportedOperationException("not implemented yet");
	}
}