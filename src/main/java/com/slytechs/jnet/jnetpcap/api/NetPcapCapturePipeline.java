package com.slytechs.jnet.jnetpcap.api;

import java.lang.foreign.MemorySegment;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapException;

import com.slytechs.jnet.core.api.memory.FixedMemory;
import com.slytechs.jnet.core.api.memory.Memory;
import com.slytechs.jnet.core.api.memory.ScopedMemory;
import com.slytechs.jnet.core.api.time.TimestampUnit;
import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.api.PacketHandler.OfPacketConsumer;
import com.slytechs.jnet.protocol.api.Packet;
import com.slytechs.jnet.protocol.api.descriptor.DescriptorTypeInfo;
import com.slytechs.jnet.protocol.api.descriptor.L2FrameType;
import com.slytechs.jnet.protocol.api.descriptor.L2FrameTypeInfo;
import com.slytechs.jnet.protocol.api.descriptor.NetPacketDescriptor;
import com.slytechs.jnet.protocol.api.descriptor.PacketDescriptor;
import com.slytechs.jnet.protocol.api.descriptor.PcapHdrDescriptor;
import com.slytechs.jnet.protocol.api.dissector.Net3PacketDissector;
import com.slytechs.jnet.protocol.api.dissector.PacketDissector;
import com.slytechs.jnet.protocol.api.stack.PacketPolicy;
import com.slytechs.jnet.protocol.api.stack.ProtocolStack;
import com.slytechs.jnet.protocol.api.stack.ProtocolStackException;
import com.slytechs.jnet.protocol.api.stack.processor.Processor;

/**
 * Package-private dispatcher that bridges pcap callbacks to ProtocolStack
 * processing.
 * 
 * <p>
 * Handles the pipeline: raw pcap callback → packet binding → stack processing →
 * user handler. Single-threaded, one instance per NetPcap handle.
 * </p>
 */
final class NetPcapCapturePipeline {

	public interface PcapProcessor {

		Packet dissectAndConvertToPacket(MemorySegment pcapHdr, MemorySegment data);

	}

	// ════════════════════════════════════════════════════════════════
	// Configuration (from ProtocolStack)
	// ════════════════════════════════════════════════════════════════

	private final ProtocolStack stack;
	// Strategy determined at construction - no runtime checks
	private final PcapProcessor pcapProcessor;
	private final Processor stackProcessor;

	// ════════════════════════════════════════════════════════════════
	// Capture context (set by NetPcap based on pcap handle state)
	// ════════════════════════════════════════════════════════════════

	private TimestampUnit timestampUnit = TimestampUnit.EPOCH_MILLI;
	private L2FrameType l2Type = L2FrameTypeInfo.ETHER;

	// ════════════════════════════════════════════════════════════════
	// Reusable objects (avoid allocation in hot path)
	// ════════════════════════════════════════════════════════════════

	private final PcapHdrDescriptor pcapHeader = new PcapHdrDescriptor();
	private final Memory descriptorMemory = new FixedMemory(1024);

	// ════════════════════════════════════════════════════════════════
	// Constructor
	// ════════════════════════════════════════════════════════════════

	NetPcapCapturePipeline(ProtocolStack stack) {
		this.stack = stack;
		this.stackProcessor = stack.getRootProcessor();

		PacketPolicy policy = stack.getPacketPolicy();

		if (policy.getMemoryPoolSettings() == null) {
			this.pcapProcessor = buildZeroCopyProcessor(stack, policy);
		} else {
			this.pcapProcessor = buildZeroCopyProcessor(stack, policy);
		}
	}

	private PcapProcessor buildZeroCopyProcessor(ProtocolStack stack, PacketPolicy policy) {
		// All finals captured in closure - no allocation in hot path
		final ScopedMemory scopedHdr = new ScopedMemory();
		final ScopedMemory scopedData = new ScopedMemory();
		final Packet packet = new Packet();
		final PacketDissector dissector = getPacketDissector(policy);

		// Reusable descriptor
		final PacketDescriptor descriptor = getPacketDescriptor(policy);
		descriptor.bind(descriptorMemory, 0);

		return (pcapHdr, data) -> {

			// Wrap native pcap memory in scoped memory
			// ScopedMemory is re-bindable, FixedMemory is not
			scopedHdr.bind(pcapHdr, 0, pcapHdr.byteSize());
			scopedData.bind(data, 0, data.byteSize());

			// Now native Pcap header descriptor so we can read basic values
			this.pcapHeader.bind(scopedHdr);
			pcapHeader.setTimestampUnit(timestampUnit);
			long ts = pcapHeader.timestamp();
			int caplen = pcapHeader.captureLength();
			int wirelen = pcapHeader.wireLength();

			// Dissect native packet
			dissector.dissectPacket(scopedData, ts, caplen, wirelen);

			// Write descriptor context to descriptor memory
			dissector.writeDescriptor(descriptor);

			// Bind the packet memory and set the dissection results in descriptor
			packet.bind(scopedData, 0);
			packet.setPacketDescriptor(descriptor);

			/*
			 * Hotpath notes: longest part is the dissection and writing the 24-96 byte
			 * descriptor from java context in dissector to native descriptor memory.
			 * Everything else is just binding which is just changing 1 reference and a
			 * couple of long fields per each binding. JIT should inline this to native
			 * speed. All of this is extremely fast after JIT.
			 */

			// Packet is ready, fully bound and dissected (L2-L4)
			return packet;
		};
	}

//	private PcapDissector buildPooledProcessor(ProtocolStack stack, PacketPolicy policy) {
//		// Pool setup
//		final MemoryPool<FixedMemory> pool = MemoryPool.create(policy.getMemoryPoolSettings());
//		final ViewPool<Packet> packetPool = null;
//		final PacketDescriptor descriptor = getPacketDescriptor(policy);
//		final PacketDissector dissector = getPacketDissector(policy);
//
//		return (pcapHdr, data) -> {
//			Packet packet = packetPool.allocate();
//
//			return packet;
//		};
//	}

	private PacketDissector getPacketDissector(PacketPolicy policy) {
		return switch (policy.getDescriptorType()) {
		case DescriptorTypeInfo.NET -> new Net3PacketDissector();

		default -> throw new ProtocolStackException("unsupported packet descriptor type " + policy.getDescriptorType());
		};
	}

	private PacketDescriptor getPacketDescriptor(PacketPolicy policy) {
		return switch (policy.getDescriptorType()) {
		case DescriptorTypeInfo.NET -> new NetPacketDescriptor();

		default -> throw new ProtocolStackException("unsupported packet descriptor type " + policy.getDescriptorType());
		};
	}

	// ════════════════════════════════════════════════════════════════
	// Configuration (called by NetPcap after handle setup)
	// ════════════════════════════════════════════════════════════════

	void setTimestampUnit(TimestampUnit unit) {
		this.timestampUnit = unit;
	}

	void setL2FrameType(L2FrameType type) {
		this.l2Type = type;
	}

	// ════════════════════════════════════════════════════════════════
	// Core packet processing
	// ════════════════════════════════════════════════════════════════

	/**
	 * Process raw pcap packet data through the protocol stack.
	 *
	 * @param pcapHdr pcap packet header (timestamp, lengths)
	 * @param data    raw packet data
	 * @return processed Packet with descriptor populated
	 */
	private Packet processPacket(MemorySegment pcapHdr, MemorySegment data) {

		Packet packet = pcapProcessor.dissectAndConvertToPacket(pcapHdr, data);

		// 5. Process through protocol stack
		// Stack handles: dissection, reassembly, decryption based on config
		Packet okOrNull = stackProcessor.processPacket(packet, null, null);

		return okOrNull;
	}

	// ════════════════════════════════════════════════════════════════
	// Dispatch methods (called by NetPcap)
	// ════════════════════════════════════════════════════════════════

	<U> int dispatch(Pcap pcap, int count, OfPacket<U> handler, U user) throws PcapException {
		return pcap.dispatch(count, (U u, MemorySegment h, MemorySegment p) -> {

			Packet packet = processPacket(h, p);

			if (packet != null)
				handler.handlePacket(u, packet);

		}, user);
	}

	int dispatch(Pcap pcap, int count, OfPacketConsumer handler) throws PcapException {
		return pcap.dispatch(count, (Void _, MemorySegment h, MemorySegment p) -> {
			Packet packet = processPacket(h, p);

			if (packet != null)
				handler.accept(packet);

		}, null);
	}

	// ════════════════════════════════════════════════════════════════
	// Loop methods (called by NetPcap)
	// ════════════════════════════════════════════════════════════════

	<U> int loop(Pcap pcap, int count, OfPacket<U> handler, U user) {
		return pcap.loop(count, (U u, MemorySegment h, MemorySegment p) -> {
			Packet packet = processPacket(h, p);

			if (packet != null)
				handler.handlePacket(u, packet);

		}, user);
	}

	int loop(Pcap pcap, int count, OfPacketConsumer handler) {
		return pcap.loop(count, (Void _, MemorySegment h, MemorySegment p) -> {
			Packet packet = processPacket(h, p);

			if (packet != null)
				handler.accept(packet);

		}, null);
	}
}