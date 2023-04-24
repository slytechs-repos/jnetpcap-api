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
package com.slytechs.jnetpcap.pro.internal.ipf;

import java.lang.foreign.MemoryAddress;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.nio.ByteBuffer;

import com.slytechs.jnetpcap.pro.IpfConfiguration;
import com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket;
import com.slytechs.jnetpcap.pro.internal.JavaPacketDispatcher;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.descriptor.IpfFragDissector;
import com.slytechs.protocol.descriptor.IpfFragment;
import com.slytechs.protocol.pack.core.constants.CoreConstants;
import com.slytechs.protocol.runtime.hash.Checksums;

/**
 * The Class JavaIpfDispatcher.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public final class JavaIpfDispatcher extends JavaPacketDispatcher implements IpfDispatcher {

	/** The ipf dissector. */
	private final IpfFragDissector ipfDissector = new IpfFragDissector();

	/** The ipf desc buffer. */
	private final ByteBuffer ipfDescBuffer = ByteBuffer.allocateDirect(CoreConstants.DESC_IPF_FRAG_BYTE_SIZE);

	/** The ipf desc. */
	private final IpfFragment ipfDesc = new IpfFragment(ipfDescBuffer);

	/** The ipf table. */
	private final IpfTable ipfTable;

	/** The ipf config. */
	private final IpfConfiguration ipfConfig;

	/**
	 * Instantiates a new java ipf dispatcher.
	 *
	 * @param pcapHandle    the pcap handle
	 * @param breakDispatch the break dispatch
	 * @param config        the config
	 */
	public JavaIpfDispatcher(
			MemoryAddress pcapHandle,
			Runnable breakDispatch,
			IpfConfig config) {
		super(pcapHandle, breakDispatch, config);
		this.ipfConfig = config;
		this.ipfTable = new IpfTable(config);
	}

	/**
	 * Dispatch ipf.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 */
	protected <U> int dispatchIpf(int count, OfPacket<U> sink, U user) {
		return super.dispatchNative(count, (ignore, pcapHdr, pktData) -> {

			try (var session = MemorySession.openShared()) {

				if (ipfConfig.isIpfPassthrough() && ipfConfig.isIpfPassthroughFragments()) {

					Packet packet = super.processPacket(pcapHdr, pktData, session);

					if (processIpfPacket(packet))
						sink.handlePacket(user, packet);

				} else {
					processIpfNative(pcapHdr, pktData, session);
				}

			}

		}, MemoryAddress.NULL); // We don't pass user object to native dispatcher
	}

	/**
	 * Dispatch packet.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 * @see com.slytechs.jnetpcap.pro.internal.JavaPacketDispatcher#dispatchPacket(int,
	 *      com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket, java.lang.Object)
	 */
	@Override
	public <U> int dispatchPacket(int count, OfPacket<U> sink, U user) {
		if (ipfConfig.isIpfEnabled())
			return this.dispatchIpf(count, sink, user);
		else
			return super.dispatchPacket(count, sink, user); // Normal, NON-IPF dispatcher
	}

	/**
	 * Loop ipf.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 */
	protected <U> int loopIpf(int count, OfPacket<U> sink, U user) {
		return super.loopNative(count, (ignore, pcapHdr, pktData) -> {

			try (var session = MemorySession.openShared()) {

				if (!ipfConfig.isIpfPassthroughFragments()) {
					processIpfNative(pcapHdr, pktData, session);
					return;
				}

				Packet packet = super.processPacket(pcapHdr, pktData, session);

				if (processIpfPacket(packet))
					sink.handlePacket(user, packet);

			}

		}, MemoryAddress.NULL); // We don't pass user object to native dispatcher
	}

	/**
	 * Loop packet.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 * @see com.slytechs.jnetpcap.pro.internal.JavaPacketDispatcher#loopPacket(int,
	 *      com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket, java.lang.Object)
	 */
	@Override
	public <U> int loopPacket(int count, OfPacket<U> sink, U user) {
		if (ipfConfig.isIpfEnabled())
			return this.loopIpf(count, sink, user);
		else
			return super.loopPacket(count, sink, user); // Normal, NON-IPF dispatcher
	}

	/**
	 * Process ipf buffer.
	 *
	 * @param frameNo   the frame no
	 * @param packetBuf the packet buf
	 * @param caplen    the caplen
	 * @param wirelen   the wirelen
	 * @param ts        the ts
	 * @return the ipf fragment
	 */
	protected IpfFragment processIpfBuffer(long frameNo, ByteBuffer packetBuf, int caplen, int wirelen, long ts) {
		ipfDissector.reset();
		boolean isIpf = ipfDissector.dissectPacket(packetBuf, ts, caplen, wirelen) > 0;
		if (!isIpf)
			return null; // No more space in IPF table

		ipfDissector.writeDescriptor(ipfDescBuffer.clear());
		ipfDescBuffer.flip();
		ipfDesc.bind(ipfDescBuffer);

		long ipfHashcode = Checksums.crc32(ipfDesc.keyBuffer());

		var reassembler = ipfTable.lookup(ipfDesc, ipfHashcode);
		if (reassembler == null)
			return null; // Drop, out of table space

		if (reassembler.processFragment(frameNo, packetBuf, ipfDesc))
			return ipfDesc;

		return null; // Processing failed
	}

	/**
	 * Process ipf native.
	 *
	 * @param pcapHdr the pcap hdr
	 * @param pktData the pkt data
	 * @param session the session
	 * @return true, if successful
	 */
	protected boolean processIpfNative(MemoryAddress pcapHdr, MemoryAddress pktData, MemorySession session) {

		int caplen = 0, wirelen = 0;
		try {
			/* Pcap header fields */
			caplen = config.abi.captureLength(pcapHdr);
			wirelen = config.abi.wireLength(pcapHdr);
			long tvSec = config.abi.tvSec(pcapHdr);
			long tvUsec = config.abi.tvUsec(pcapHdr);

			long timestamp = config.timestampUnit.ofSecond(tvSec, tvUsec);

			MemorySegment mpkt = MemorySegment.ofAddress(pktData, caplen, session);
			ByteBuffer buf = mpkt.asByteBuffer();

			boolean isSuccess = (processIpfBuffer(-1, buf, caplen, wirelen, timestamp) != null);

			if (isSuccess)
				incPacketReceived(caplen, wirelen);
			else
				incPacketDropped(caplen, wirelen);

			return isSuccess;

		} catch (Throwable e) {
			incPacketDropped(caplen, wirelen);
			onNativeCallbackException(e, caplen, wirelen);
			return false;
		}
	}

	/**
	 * Process ipf packet.
	 *
	 * @param packet the packet
	 * @return true, if successful
	 */
	protected boolean processIpfPacket(Packet packet) {
		ByteBuffer buf = packet.buffer();
		int caplen = packet.captureLength();
		int wirelen = packet.wireLength();
		long ts = packet.timestamp();
		long frameNo = packet.descriptor().frameNo();

		IpfFragment ipfDesc = processIpfBuffer(frameNo, buf, caplen, wirelen, ts);
		if (ipfDesc != null) {
			super.incPacketReceived(caplen, wirelen);
			packet.descriptor().addDescriptor(ipfDesc);

		} else
			super.incPacketDropped(caplen, wirelen);

		return (ipfDesc != null);
	}

}
