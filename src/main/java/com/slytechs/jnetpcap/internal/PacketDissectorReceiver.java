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
package com.slytechs.jnetpcap.internal;

import static com.slytechs.protocol.runtime.internal.foreign.ForeignUtils.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

import org.jnetpcap.PcapException;
import org.jnetpcap.internal.PcapDispatcher;
import org.jnetpcap.util.PcapPacketRef;

import com.slytechs.jnetpcap.CaptureStatistics;
import com.slytechs.jnetpcap.PcapProHandler;
import com.slytechs.jnetpcap.PcapProHandler.OfPacket;
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
public class PacketDissectorReceiver
		implements PacketReceiver {

	/** The Constant DESC_BUFFER_SIZE. */
	private static final int DESC_BUFFER_SIZE = 1024;

	/** The singleton desc buffer. */
	private final ByteBuffer reusableDescBuffer;

	/** The singleton packet. */
	private Packet reusablePacket;

	/** The config. */
	protected final PacketReceiverConfig config;

	/** The stats. */
	protected final CaptureStatisticsImpl stats = (CaptureStatisticsImpl) CaptureStatistics.newInstance();

	/** The pcap dispatcher. */
	protected PcapDispatcher pcapDispatcher;

	/** The one time session. */
	private Arena oneTimeSession;

	/**
	 * Instantiates a new packet dispatcher.
	 *
	 * @param config the config
	 */
	public PacketDissectorReceiver(
			PacketReceiverConfig config) {

		this.config = config;
		this.reusableDescBuffer = ByteBuffer
				.allocateDirect(PacketDissectorReceiver.DESC_BUFFER_SIZE)
				.order(ByteOrder.nativeOrder());
	}

	/**
	 * Activate.
	 *
	 * @see com.slytechs.jnetpcap.internal.PacketReceiver#activate()
	 */
	@Override
	public void activate() {
		this.reusablePacket = new Packet(config.descriptorType.newDescriptor());
	}

	/**
	 * Close.
	 *
	 * @see com.slytechs.jnetpcap.internal.PacketReceiver#close()
	 */
	@Override
	public void close() {
	}

	/**
	 * Creates the packet.
	 *
	 * @param bpkt      the bpkt
	 * @param mpacket   the packet
	 * @param caplen    the caplen
	 * @param wirelen   the wirelen
	 * @param timestamp the timestamp
	 * @return the packet
	 */
	protected Packet createSingletonPacket(ByteBuffer bpkt, MemorySegment mpacket, int caplen, int wirelen,
			long timestamp) {

		config.dissector.dissectPacket(bpkt, timestamp, caplen, wirelen);
		config.dissector.writeDescriptor(reusableDescBuffer.clear());
		config.dissector.reset();

		Packet packet = reusablePacket;
		PacketDescriptor desc = packet.descriptor();

		packet.bind(bpkt.flip(), mpacket);
		desc.bind(reusableDescBuffer.flip());

		desc.frameNo(config.frameNo.getUsing(timestamp, config.portNo));
		desc.timestampUnit(config.timestampUnit);
		packet.setFormatter(config.formatter);
		desc.timestampUnit(config.timestampUnit);

		return packet;
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
		config.dissector.writeDescriptor(reusableDescBuffer.clear());
		config.dissector.reset();

		Packet packet = reusablePacket;
		PacketDescriptor desc = packet.descriptor();

		packet.bind(bpkt.flip(), mpacket);
		desc.bind(reusableDescBuffer.flip());

		desc.portNo(config.portNo);
		desc.portName(config.portName);
		desc.frameNo(config.frameNo.getUsing(timestamp, config.portNo));
		desc.timestampUnit(config.timestampUnit);
		packet.setFormatter(config.formatter);
		desc.timestampUnit(config.timestampUnit);

		return packet;
	}

	/**
	 * Gets the capture statistics.
	 *
	 * @return the capture statistics
	 * @see com.slytechs.jnetpcap.pro.PacketReceiver#getCaptureStatistics()
	 */
	@Override
	public CaptureStatistics getCaptureStatistics() {
		return stats;
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
	 * Gets the dropped caplen count.
	 *
	 * @return the dropped caplen count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getDroppedCaplenCount()
	 */
	public long getDroppedCaplenCount() {
		return stats.getDroppedCaplenCount();
	}

	/**
	 * Gets the dropped packet count.
	 *
	 * @return the dropped packet count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getDroppedPacketCount()
	 */
	public long getDroppedPacketCount() {
		return stats.getDroppedPacketCount();
	}

	/**
	 * Gets the dropped wirelen count.
	 *
	 * @return the dropped wirelen count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getDroppedWirelenCount()
	 */
	public long getDroppedWirelenCount() {
		return stats.getDroppedWirelenCount();
	}

	/**
	 * Gets the onetime memory session. The memory session mimics how Pcap next and
	 * nextEx returned packet's behave. They are only valid until the next call.
	 *
	 * @return the onetime memory session
	 */
	private Arena getOnetimeSegmentScope() {
		if (oneTimeSession != null)
			oneTimeSession.close();

		return oneTimeSession = Arena.ofShared();
	}

	/**
	 * Gets the packet with next.
	 *
	 * @return the packet with next
	 * @throws PcapException the pcap exception
	 * @see com.slytechs.jnetpcap.internal.PacketReceiver#getPacketWithNext()
	 */
	@Override
	public Packet getPacketWithNext() throws PcapException {
		PcapPacketRef packetRef = pcapDispatcher.next();

		MemorySegment pcapHdr = packetRef.header();
		MemorySegment pktData = packetRef.data();

		int caplen = 0, wirelen = 0;

		/* Pcap header fields */
		caplen = config.abi.captureLength(pcapHdr);
		wirelen = config.abi.wireLength(pcapHdr);
		long tvSec = config.abi.tvSec(pcapHdr);
		long tvUsec = config.abi.tvUsec(pcapHdr);

		long timestamp = config.timestampUnit.ofSecond(tvSec, tvUsec);

		MemorySegment mpkt = pktData.reinterpret(caplen, getOnetimeSegmentScope(), EMPTY_CLEANUP);

		Packet packet = createSingletonPacket(mpkt, caplen, wirelen, timestamp);

		stats.incReceived(caplen, wirelen, 1);

		return packet;
	}

	/**
	 * Gets the packet with next extended.
	 *
	 * @return the packet with next extended
	 * @throws PcapException    the pcap exception
	 * @throws TimeoutException the timeout exception
	 * @see com.slytechs.jnetpcap.internal.PacketReceiver#getPacketWithNextExtended()
	 */
	@Override
	public Packet getPacketWithNextExtended() throws PcapException, TimeoutException {
		PcapPacketRef packetRef = pcapDispatcher.nextEx();

		MemorySegment pcapHdr = packetRef.header();
		MemorySegment pktData = packetRef.data();

		int caplen = 0, wirelen = 0;

		/* Pcap header fields */
		caplen = config.abi.captureLength(pcapHdr);
		wirelen = config.abi.wireLength(pcapHdr);
		long tvSec = config.abi.tvSec(pcapHdr);
		long tvUsec = config.abi.tvUsec(pcapHdr);

		long timestamp = config.timestampUnit.ofSecond(tvSec, tvUsec);

		MemorySegment mpkt = pktData.reinterpret(caplen, getOnetimeSegmentScope(), EMPTY_CLEANUP);

		Packet packet = createSingletonPacket(mpkt, caplen, wirelen, timestamp);

		stats.incReceived(caplen, wirelen, 1);

		return packet;
	}

	/**
	 * Gets the received caplen count.
	 *
	 * @return the received caplen count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getReceivedCaplenCount()
	 */
	public long getReceivedCaplenCount() {
		return stats.getReceivedCaplenCount();
	}

	/**
	 * Gets the received packet count.
	 *
	 * @return the received packet count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getReceivedPacketCount()
	 */
	public long getReceivedPacketCount() {
		return stats.getReceivedPacketCount();
	}

	/**
	 * Gets the received wirelen count.
	 *
	 * @return the received wirelen count
	 * @see com.slytechs.jnetpcap.CaptureStatistics#getReceivedWirelenCount()
	 */
	public long getReceivedWirelenCount() {
		return stats.getReceivedWirelenCount();
	}

	/**
	 * Inc packet dropped.
	 *
	 * @param caplen  the caplen
	 * @param wirelen the wirelen
	 */
	protected void incPacketDropped(int caplen, int wirelen) {
		stats.incDropped(caplen, wirelen, 1);
	}

	/**
	 * Inc packet received.
	 *
	 * @param caplen  the caplen
	 * @param wirelen the wirelen
	 */
	protected void incPacketReceived(int caplen, int wirelen) {
		stats.incReceived(caplen, wirelen, 1);
	}

	/**
	 * On native callback exception.
	 *
	 * @param e       the e
	 * @param caplen  the caplen
	 * @param wirelen the wirelen
	 */
	private void onNativeCallbackException(RuntimeException e, int caplen, int wirelen) {
		stats.incDropped(caplen, wirelen, 1);

		pcapDispatcher.onNativeCallbackException(e);
	}

	/**
	 * @see com.slytechs.jnetpcap.internal.PacketReceiver#onNativeCallbackException(java.lang.Throwable, int, int)
	 */
	@Override
	public void onNativeCallbackException(Throwable e, int caplen, int wirelen) {
		if (e instanceof RuntimeException runtime)
			onNativeCallbackException(runtime, caplen, wirelen);
		else
			pcapDispatcher.onNativeCallbackException(new IllegalStateException("unable to process packet", e));
	}

	/**
	 * @see com.slytechs.jnetpcap.internal.PacketReceiver#processPacket(java.nio.ByteBuffer, java.lang.foreign.MemorySegment, int, int, long)
	 */
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

	/**
	 * Process packet.
	 *
	 * @param <U>     the generic type
	 * @param pcapHdr the pcap hdr
	 * @param pktData the pkt data
	 * @param arena   the arena
	 * @return the packet
	 * @see com.slytechs.jnetpcap.internal.PacketReceiver#processPacket(java.lang.foreign.MemorySegment,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.Arena)
	 */
	@Override
	public <U> Packet processPacket(
			MemorySegment pcapHdr,
			MemorySegment pktData,
			Arena arena) {

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

			Packet packet = createSingletonPacket(pktData, caplen, wirelen, timestamp);

			stats.incReceived(caplen, wirelen, 1);

			return packet;

		} catch (Throwable e) {
			stats.incDropped(caplen, wirelen, 1);
			onNativeCallbackException(e, caplen, wirelen);
			return null;
		}
	}

	/**
	 * Receive packet with dispatch.
	 *
	 * @param <U>           the generic type
	 * @param count         the count
	 * @param sink          the sink
	 * @param user          the user
	 * @param packetFactory the packet factory
	 * @return the int
	 * @see com.slytechs.jnetpcap.internal.PacketReceiver#receivePacketWithDispatch(int,
	 *      com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket, java.lang.Object,
	 *      java.util.function.Supplier)
	 */
	@Override
	public <U> int receivePacketWithDispatch(int count, OfPacket<U> sink, U user, Supplier<Packet> packetFactory) {
		return pcapDispatcher.dispatchNative(count, (ignore, pcapHdr, pktData) -> {

			try (var arena = Arena.ofShared()) {

				Packet packet = processPacket(pcapHdr, pktData, arena);
				if (packet != null)
					sink.handlePacket(user, packet);

			}

		}, MemorySegment.NULL); // We don't pass user object to native dispatcher
	}
	
	/**
	 * Gets the singleton packet.
	 *
	 * @return the singleton packet
	 */
	private Packet getReusablePacket() {
		return this.reusablePacket;
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
	public <U> int receivePacketWithDispatch(int count, PcapProHandler.OfPacket<U> sink, U user) {
		return receivePacketWithDispatch(count, sink, user, this::getReusablePacket);
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
	public <U> int receivePacketWithLoop(int count, PcapProHandler.OfPacket<U> sink, U user) {
		return pcapDispatcher.loopNative(count, (ignore, pcapHdr, pktData) -> {

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

				Packet packet = createSingletonPacket(pktData, caplen, wirelen, timestamp);

				stats.incReceived(caplen, wirelen, 1);

				sink.handlePacket(user, packet);
			} catch (Throwable e) {
				onNativeCallbackException(e, caplen, wirelen);
			}

		}, MemorySegment.NULL);
	}

	/**
	 * Sets the pcap dispatcher.
	 *
	 * @param pcapDispatcher the new pcap dispatcher
	 */
	public void setPcapDispatcher(PcapDispatcher pcapDispatcher) {
		this.pcapDispatcher = pcapDispatcher;
	}

}
