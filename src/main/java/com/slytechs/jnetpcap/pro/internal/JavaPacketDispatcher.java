/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnetpcap.pro.internal;

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.internal.StandardPcapDispatcher;

import com.slytechs.jnetpcap.pro.PacketDispatcher;
import com.slytechs.jnetpcap.pro.PcapProHandler;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.descriptor.PacketDescriptor;
import com.slytechs.protocol.descriptor.PacketDissector;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;

/**
 * A packet dissector and dispatcher.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class JavaPacketDispatcher
		extends StandardPcapDispatcher
		implements PacketDispatcher {

	/** The Constant DESC_BUFFER_SIZE. */
	private static final int DESC_BUFFER_SIZE = 1024;

	/** The singleton desc buffer. */
	private final ByteBuffer singletonDescBuffer;

	/** The singleton packet. */
	private final Packet singletonPacket;

	/** The port no. */
	private int portNo;

	protected final PacketDispatcherConfig config;

	protected final PacketStatisticsImpl stats = (PacketStatisticsImpl) PacketStatistics.newInstance();

	/**
	 * Instantiates a new packet dispatcher.
	 *
	 * @param pcapHandle     the pcap handle
	 * @param breakDispatch  the break dispatch
	 * @param descriptorType the descriptor type
	 */
	public JavaPacketDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			PacketDispatcherConfig config) {
		super(pcapHandle, breakDispatch);

		this.config = config;
		this.singletonDescBuffer = ByteBuffer
				.allocateDirect(DESC_BUFFER_SIZE)
				.order(ByteOrder.nativeOrder());

		this.singletonPacket = new Packet(config.descriptorType.newDescriptor());
	}

	/**
	 * Creates the packet.
	 *
	 * @param mpacket   the packet
	 * @param caplen    the caplen
	 * @param wirelen   the wirelen
	 * @param timestamp the timestamp
	 * @return the packet
	 */
	protected Packet createSingletonPacket(MemorySegment mpacket, int caplen, int wirelen, long timestamp) {
		ByteBuffer bpkt = mpacket.asByteBuffer();

		config.dissector.dissectPacket(bpkt, timestamp, caplen, wirelen);
		config.dissector.writeDescriptor(singletonDescBuffer.clear());
		config.dissector.reset();

		Packet packet = singletonPacket;
		PacketDescriptor desc = packet.descriptor();

		packet.bind(bpkt.flip(), mpacket);
		desc.bind(singletonDescBuffer.flip());

		desc.frameNo(config.frameNo.getUsing(timestamp, portNo));
		desc.timestampUnit(config.timestampUnit);
		packet.setFormatter(config.formatter);
		desc.timestampUnit(config.timestampUnit);

		return packet;
	}

	/**
	 * Creates the packet.
	 * 
	 * @param mpacket   TODO
	 * @param caplen    the caplen
	 * @param wirelen   the wirelen
	 * @param timestamp the timestamp
	 * @param mpacket   the packet
	 *
	 * @return the packet
	 */
	protected Packet createSingletonPacket(ByteBuffer bpkt, MemorySegment mpacket, int caplen, int wirelen,
			long timestamp) {

		config.dissector.dissectPacket(bpkt, timestamp, caplen, wirelen);
		config.dissector.writeDescriptor(singletonDescBuffer.clear());
		config.dissector.reset();

		Packet packet = singletonPacket;
		PacketDescriptor desc = packet.descriptor();

		packet.bind(bpkt.flip(), mpacket);
		desc.bind(singletonDescBuffer.flip());

		desc.frameNo(config.frameNo.getUsing(timestamp, portNo));
		desc.timestampUnit(config.timestampUnit);
		packet.setFormatter(config.formatter);
		desc.timestampUnit(config.timestampUnit);

		return packet;
	}

	/**
	 * Dispatch packet.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 */
	@Override
	public <U> int dispatchPacket(int count, PcapProHandler.OfPacket<U> sink, U user) {
		return super.dispatchNative(count, (ignore, pcapHdr, pktData) -> {

			try (var session = MemorySession.openShared()) {

				Packet packet = processPacket(pcapHdr, pktData, session);
				if (packet != null)
					sink.handlePacket(user, packet);

			}

		}, MemoryAddress.NULL); // We don't pass user object to native dispatcher
	}

	protected <U> Packet processPacket(
			MemoryAddress pcapHdr,
			MemoryAddress pktData,
			MemorySession session) {

		/*
		 * Initialize outside the try-catch to attempt to read caplen for any exceptions
		 * thrown
		 */
		int caplen = 0, wirelen = 0;
		try {
			/* Pcap header fields */
			caplen = config.abi.captureLength(pcapHdr);
			wirelen = config.abi.wireLength(pcapHdr);
			long tvSec = config.abi.tvSec(pcapHdr);
			long tvUsec = config.abi.tvUsec(pcapHdr);

			long timestamp = config.timestampUnit.ofSecond(tvSec, tvUsec);

			MemorySegment mpkt = MemorySegment.ofAddress(pktData, caplen, session);

			Packet packet = createSingletonPacket(mpkt, caplen, wirelen, timestamp);

			incPacketReceived(caplen, wirelen);

			return packet;

		} catch (Throwable e) {
			incPacketDropped(caplen, wirelen);
			onNativeCallbackException(e, caplen, wirelen);
			return null;
		}
	}

	protected <U> Packet processPacket(
			ByteBuffer buffer,
			MemorySegment mpacket,
			int caplen,
			int wirelen,
			long timestamp) {

		Packet packet = createSingletonPacket(buffer, mpacket, caplen, wirelen, timestamp);

		incPacketReceived(caplen, wirelen);

		return packet;
	}

	protected void incPacketReceived(int caplen, int wirelen) {
		stats.incReceived(caplen, wirelen, 1);
	}

	protected void incPacketDropped(int caplen, int wirelen) {
		stats.incDropped(caplen, wirelen, 1);
	}

	/**
	 * Gets the descriptor type.
	 *
	 * @return the descriptorType
	 */
	@Override
	public PacketDescriptorType getDescriptorType() {
		return config.descriptorType;
	}

	/**
	 * Gets the current dissector.
	 *
	 * @return the dissector
	 */
	@Override
	public PacketDissector getDissector() {
		return config.dissector;
	}

	/**
	 * Loop packet.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 */
	@Override
	public <U> int loopPacket(int count, PcapProHandler.OfPacket<U> sink, U user) {
		return super.loopNative(count, (ignore, pcapHdr, pktData) -> {

			/*
			 * Initialize outside the try-catch to attempt to read caplen for any exceptions
			 * thrown
			 */
			int caplen = 0, wirelen = 0;

			try (var session = MemorySession.openShared()) {

				/* Pcap header fields */
				caplen = config.abi.captureLength(pcapHdr);
				wirelen = config.abi.wireLength(pcapHdr);
				long tvSec = config.abi.tvSec(pcapHdr);
				long tvUsec = config.abi.tvUsec(pcapHdr);

				long timestamp = config.timestampUnit.ofSecond(tvSec, tvUsec);

				MemorySegment mpkt = MemorySegment.ofAddress(pktData, caplen, session);

				Packet packet = createSingletonPacket(mpkt, caplen, wirelen, timestamp);

				stats.incReceived(caplen, wirelen, 1);

				sink.handlePacket(user, packet);
			} catch (Throwable e) {
				onNativeCallbackException(e, caplen, wirelen);
			}

		}, MemoryAddress.NULL);
	}

	protected void onNativeCallbackException(Throwable e, int caplen, int wirelen) {
		if (e instanceof RuntimeException runtime)
			onNativeCallbackException(runtime, caplen, wirelen);
		else
			onNativeCallbackException(new IllegalStateException("unable to process packet", e));
	}

	private void onNativeCallbackException(RuntimeException e, int caplen, int wirelen) {
		stats.incDropped(caplen, wirelen, 1);

		super.onNativeCallbackException(e);
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getDroppedCaplenCount()
	 */
	public long getDroppedCaplenCount() {
		return stats.getDroppedCaplenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getDroppedPacketCount()
	 */
	public long getDroppedPacketCount() {
		return stats.getDroppedPacketCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getDroppedWirelenCount()
	 */
	public long getDroppedWirelenCount() {
		return stats.getDroppedWirelenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getReceivedCaplenCount()
	 */
	public long getReceivedCaplenCount() {
		return stats.getReceivedCaplenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getReceivedPacketCount()
	 */
	public long getReceivedPacketCount() {
		return stats.getReceivedPacketCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketStatistics#getReceivedWirelenCount()
	 */
	public long getReceivedWirelenCount() {
		return stats.getReceivedWirelenCount();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PacketDispatcher#getPacketStatistics()
	 */
	@Override
	public PacketStatistics getPacketStatistics() {
		return stats;
	}

}
