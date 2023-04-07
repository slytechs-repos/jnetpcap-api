/*
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.jnetpcap.pro.internal;

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.internal.PcapHeaderABI;
import org.jnetpcap.internal.StandardPcapDispatcher;

import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.Frame.FrameNumber;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.descriptor.PacketDescriptor;
import com.slytechs.jnet.protocol.descriptor.PacketDissector;
import com.slytechs.jnet.protocol.meta.PacketFormat;
import com.slytechs.jnet.runtime.time.TimestampUnit;
import com.slytechs.jnetpcap.pro.PcapProHandler;

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

	private static final int DESC_BUFFER_SIZE = 1024;

	private static final PcapHeaderABI ABI = PcapHeaderABI.nativeAbi();

	private final PacketDissector dissector;
	private final PacketDescriptorType descriptorType;
	private final TimestampUnit timestampUnit = TimestampUnit.PCAP_MICRO;
	private final ByteBuffer singletonDescBuffer;
	private final Packet singletonPacket;

	private FrameNumber frameNo;
	private PacketFormat formatter;
	private int portNo;

	/**
	 * Instantiates a new packet dispatcher.
	 *
	 * @param pcapHandle     the pcap handle
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

	@Override
	public void setFrameNumber(FrameNumber frameNumberAssigner) {
		this.frameNo = frameNumberAssigner;
	}

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
	 * @return the descriptorType
	 */
	@Override
	public PacketDescriptorType getDescriptorType() {
		return descriptorType;
	}

	/**
	 * @return the dissector
	 */
	@Override
	public PacketDissector getDissector() {
		return dissector;
	}

	@Override
	public void setPortNumber(int portNo) {
		this.portNo = portNo;
	}
}
