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
import java.util.concurrent.TimeoutException;

import org.jnetpcap.PcapException;
import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.util.PcapPacketRef;

import com.slytechs.jnetpcap.pro.CaptureStatistics;
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
public class MainPacketDispatcher
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

	protected final CaptureStatisticsImpl stats = (CaptureStatisticsImpl) CaptureStatistics.newInstance();

	protected PcapDispatcher pcapDispatcher;

	/**
	 * Instantiates a new packet dispatcher.
	 *
	 * @param pcapHandle     the pcap handle
	 * @param breakDispatch  the break dispatch
	 * @param descriptorType the descriptor type
	 */
	public MainPacketDispatcher(
			PacketDispatcherConfig config) {

		this.config = config;
		this.singletonDescBuffer = ByteBuffer
				.allocateDirect(DESC_BUFFER_SIZE)
				.order(ByteOrder.nativeOrder());

		this.singletonPacket = new Packet(config.descriptorType.newDescriptor());
	}

	public void setPcapDispatcher(PcapDispatcher pcapDispatcher) {
		this.pcapDispatcher = pcapDispatcher;
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
		return pcapDispatcher.dispatchNative(count, (ignore, pcapHdr, pktData) -> {

			try (var session = MemorySession.openShared()) {

				Packet packet = processPacket(pcapHdr, pktData, session);
				if (packet != null)
					sink.handlePacket(user, packet);

			}

		}, MemoryAddress.NULL); // We don't pass user object to native dispatcher
	}

	@Override
	public <U> Packet processPacket(
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

			stats.incReceived(caplen, wirelen, 1);

			return packet;

		} catch (Throwable e) {
			stats.incDropped(caplen, wirelen, 1);
			onNativeCallbackException(e, caplen, wirelen);
			return null;
		}
	}

	@Override
	public <U> Packet processPacket(
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
		return pcapDispatcher.loopNative(count, (ignore, pcapHdr, pktData) -> {

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

	@Override
	public void onNativeCallbackException(Throwable e, int caplen, int wirelen) {
		if (e instanceof RuntimeException runtime)
			onNativeCallbackException(runtime, caplen, wirelen);
		else
			pcapDispatcher.onNativeCallbackException(new IllegalStateException("unable to process packet", e));
	}

	private void onNativeCallbackException(RuntimeException e, int caplen, int wirelen) {
		stats.incDropped(caplen, wirelen, 1);

		pcapDispatcher.onNativeCallbackException(e);
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getDroppedCaplenCount()
	 */
	public long getDroppedCaplenCount() {
		return stats.getDroppedCaplenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getDroppedPacketCount()
	 */
	public long getDroppedPacketCount() {
		return stats.getDroppedPacketCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getDroppedWirelenCount()
	 */
	public long getDroppedWirelenCount() {
		return stats.getDroppedWirelenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getReceivedCaplenCount()
	 */
	public long getReceivedCaplenCount() {
		return stats.getReceivedCaplenCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getReceivedPacketCount()
	 */
	public long getReceivedPacketCount() {
		return stats.getReceivedPacketCount();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.CaptureStatistics#getReceivedWirelenCount()
	 */
	public long getReceivedWirelenCount() {
		return stats.getReceivedWirelenCount();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.PacketDispatcher#getCaptureStatistics()
	 */
	@Override
	public CaptureStatistics getCaptureStatistics() {
		return stats;
	}

	private MemorySession oneTimeSession;

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketDispatcher#nextExPacket()
	 */
	@Override
	public Packet nextExPacket() throws PcapException, TimeoutException {
		PcapPacketRef packetRef = pcapDispatcher.nextEx();

		MemoryAddress pcapHdr = packetRef.header().address();
		MemoryAddress pktData = packetRef.data().address();

		int caplen = 0, wirelen = 0;

		/* Pcap header fields */
		caplen = config.abi.captureLength(pcapHdr);
		wirelen = config.abi.wireLength(pcapHdr);
		long tvSec = config.abi.tvSec(pcapHdr);
		long tvUsec = config.abi.tvUsec(pcapHdr);

		long timestamp = config.timestampUnit.ofSecond(tvSec, tvUsec);

		MemorySegment mpkt = MemorySegment.ofAddress(pktData, caplen, getOnetimeMemorySession());

		Packet packet = createSingletonPacket(mpkt, caplen, wirelen, timestamp);

		stats.incReceived(caplen, wirelen, 1);

		return packet;
	}

	/**
	 * Gets the onetime memory session. The memory session mimics how Pcap next and
	 * nextEx returned packet's behave. They are only valid until the next call.
	 *
	 * @return the onetime memory session
	 */
	private MemorySession getOnetimeMemorySession() {
		if (oneTimeSession != null)
			oneTimeSession.close();

		return oneTimeSession = MemorySession.openShared();
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketDispatcher#nextPacket()
	 */
	@Override
	public Packet nextPacket() throws PcapException {
		PcapPacketRef packetRef = pcapDispatcher.next();

		MemoryAddress pcapHdr = packetRef.header().address();
		MemoryAddress pktData = packetRef.data().address();

		int caplen = 0, wirelen = 0;

		/* Pcap header fields */
		caplen = config.abi.captureLength(pcapHdr);
		wirelen = config.abi.wireLength(pcapHdr);
		long tvSec = config.abi.tvSec(pcapHdr);
		long tvUsec = config.abi.tvUsec(pcapHdr);

		long timestamp = config.timestampUnit.ofSecond(tvSec, tvUsec);

		MemorySegment mpkt = MemorySegment.ofAddress(pktData, caplen, getOnetimeMemorySession());

		Packet packet = createSingletonPacket(mpkt, caplen, wirelen, timestamp);

		stats.incReceived(caplen, wirelen, 1);

		return packet;
	}

}
