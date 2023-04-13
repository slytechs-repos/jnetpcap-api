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

import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.internal.StandardPcapDispatcher;

import com.slytechs.jnetpcap.pro.PcapProHandler;
import com.slytechs.protocol.Frame.FrameNumber;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.descriptor.PacketDescriptor;
import com.slytechs.protocol.descriptor.PacketDissector;
import com.slytechs.protocol.meta.PacketFormat;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;
import com.slytechs.protocol.runtime.time.TimestampUnit;

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

	/** The Constant ABI. */
	private static final PcapHeaderABI ABI = PcapHeaderABI.nativeAbi();

	/** The dissector. */
	private final PacketDissector dissector;

	/** The descriptor type. */
	private final PacketDescriptorType descriptorType;

	/** The timestamp unit. */
	private final TimestampUnit timestampUnit = TimestampUnit.PCAP_MICRO;

	/** The singleton desc buffer. */
	private final ByteBuffer singletonDescBuffer;

	/** The singleton packet. */
	private final Packet singletonPacket;

	/** The frame no. */
	private FrameNumber frameNo;

	/** The formatter. */
	private PacketFormat formatter;

	/** The port no. */
	private int portNo;

	/**
	 * Instantiates a new packet dispatcher.
	 *
	 * @param pcapHandle     the pcap handle
	 * @param breakDispatch  the break dispatch
	 * @param descriptorType the descriptor type
	 */
	public JavaPacketDispatcher(MemoryAddress pcapHandle, Runnable breakDispatch, PacketDescriptorType descriptorType) {
		super(pcapHandle, breakDispatch);
		this.descriptorType = descriptorType;
		this.dissector = PacketDissector.dissector(descriptorType);
		this.singletonDescBuffer = ByteBuffer.allocateDirect(DESC_BUFFER_SIZE)
				.order(ByteOrder.nativeOrder());

		this.singletonPacket = new Packet(descriptorType.newDescriptor());
		this.frameNo = FrameNumber.starting(0);
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketDispatcher#setFrameNumber(com.slytechs.protocol.Frame.FrameNumber)
	 */
	@Override
	public void setFrameNumber(FrameNumber frameNumberAssigner) {
		this.frameNo = frameNumberAssigner;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketDispatcher#setPacketFormat(com.slytechs.protocol.meta.PacketFormat)
	 */
	@Override
	public void setPacketFormat(PacketFormat newFormat) {
		this.formatter = newFormat;
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
	private Packet createSingletonPacket(MemorySegment mpacket, int caplen, int wirelen, long timestamp) {
		ByteBuffer bpkt = mpacket.asByteBuffer();

		dissector.dissectPacket(bpkt, timestamp, caplen, wirelen);
		dissector.writeDescriptor(singletonDescBuffer.clear());
		dissector.reset();

		Packet packet = singletonPacket;
		PacketDescriptor desc = packet.descriptor();

		packet.bind(bpkt.flip(), mpacket);
		desc.bind(singletonDescBuffer.flip());

		desc.frameNo(frameNo.getUsing(timestamp, portNo));
		desc.timestampUnit(timestampUnit);
		packet.setFormatter(formatter);

		return packet;
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
			/* Pcap header fields */
			int caplen = ABI.captureLength(pcapHdr);
			int wirelen = ABI.wireLength(pcapHdr);
			long tvSec = ABI.tvSec(pcapHdr);
			long tvUsec = ABI.tvUsec(pcapHdr);

			long timestamp = timestampUnit.ofSecond(tvSec, tvUsec);

			try (var session = MemorySession.openShared()) {
				MemorySegment mpkt = MemorySegment.ofAddress(pktData, caplen, session);

				Packet packet = createSingletonPacket(mpkt, caplen, wirelen, timestamp);

				sink.handlePacket(user, packet);
			}

		}, MemoryAddress.NULL);
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

			/* Pcap header fields */
			int caplen = ABI.captureLength(pcapHdr);
			int wirelen = ABI.wireLength(pcapHdr);
			long tvSec = ABI.tvSec(pcapHdr);
			long tvUsec = ABI.tvUsec(pcapHdr);

			long timestamp = timestampUnit.ofSecond(tvSec, tvUsec);

			try (var session = MemorySession.openShared()) {
				MemorySegment mpkt = MemorySegment.ofAddress(pktData, caplen, session);

				Packet packet = createSingletonPacket(mpkt, caplen, wirelen, timestamp);

				sink.handlePacket(user, packet);
			}

		}, MemoryAddress.NULL); // We don't pass user object to native dispatcher
	}

	/**
	 * Gets the descriptor type.
	 *
	 * @return the descriptorType
	 */
	@Override
	public PacketDescriptorType getDescriptorType() {
		return descriptorType;
	}

	/**
	 * Gets the dissector.
	 *
	 * @return the dissector
	 */
	@Override
	public PacketDissector getDissector() {
		return dissector;
	}

	/**
	 * @see com.slytechs.jnetpcap.pro.internal.PacketDispatcher#setPortNumber(int)
	 */
	@Override
	public void setPortNumber(int portNo) {
		this.portNo = portNo;
	}
}
