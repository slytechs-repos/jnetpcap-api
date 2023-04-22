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

import com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket;
import com.slytechs.jnetpcap.pro.internal.JavaPacketDispatcher;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.descriptor.IpfFragDescriptor;
import com.slytechs.protocol.descriptor.IpfFragDissector;
import com.slytechs.protocol.pack.core.constants.CoreConstants;
import com.slytechs.protocol.runtime.hash.Checksums;
import com.slytechs.protocol.runtime.util.Detail;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
 */
public class JavaIpfDispatcher extends JavaPacketDispatcher implements IpfDispatcher {

	private final IpfFragDissector ipfDissector = new IpfFragDissector();
	private final ByteBuffer ipfDescBuffer = ByteBuffer.allocateDirect(CoreConstants.DESC_IPF_FRAG_BYTE_SIZE);

	private final IpfFragDescriptor ipfDesc = new IpfFragDescriptor(ipfDescBuffer);
	private final IpfTable ipfTable;
	private final IpfConfig ipfConfig;

	/**
	 * @param pcapHandle
	 * @param breakDispatch
	 * @param descriptorType
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
	 * @see com.slytechs.jnetpcap.pro.internal.JavaPacketDispatcher#dispatchPacket(int,
	 *      com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket, java.lang.Object)
	 */
	@Override
	public <U> int dispatchPacket(int count, OfPacket<U> sink, U user) {
		return dispatchIpf(count, sink, user);
	}

	protected <U> int dispatchIpf(int count, OfPacket<U> sink, U user) {
		return super.dispatchNative(count, (ignore, pcapHdr, pktData) -> {
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
				ByteBuffer buf = mpkt.asByteBuffer();

				ipfDissector.reset();
				boolean isIpf = ipfDissector.dissectPacket(buf, timestamp, caplen, wirelen) > 0;
				if (!isIpf)
					super.processAndSink(sink, user, pcapHdr, pktData);

				ipfDissector.writeDescriptor(ipfDescBuffer.clear());
				ipfDescBuffer.flip();

				long ipfHashcode = Checksums.crc32(ipfDesc.keyBuffer());

				var reassembler = ipfTable.lookup(ipfDesc, ipfHashcode);
				if (reassembler == null) {
					droppedPacketCounter++;
					droppedCaplenCounter += caplen;
					droppedWirelenCounter += wirelen;

					return; // Drop, out of table space
				}

				reassembler.processFragment(buf, ipfDesc);

				System.out.println("dispatchIpf: " + reassembler.toString(Detail.HIGH));

				Packet packet = createSingletonPacket(mpkt, caplen, wirelen, timestamp);
				if (isIpf) {
					ipfDesc.bind(ipfDescBuffer);
					packet.descriptor().addDescriptor(ipfDesc);
				}

				receiveCaplenCounter += caplen;
				receiveWirelenCounter += wirelen;
				receivePacketCounter++;

				sink.handlePacket(user, packet);

			} catch (Throwable e) {
				onNativeCallbackException(e, caplen, wirelen);
			}

		}, MemoryAddress.NULL); // We don't pass user object to native dispatcher
	}
}
