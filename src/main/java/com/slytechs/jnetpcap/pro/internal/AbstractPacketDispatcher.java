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
import java.util.Objects;
import java.util.concurrent.TimeoutException;

import org.jnetpcap.PcapException;
import org.jnetpcap.internal.PcapDispatcher;

import com.slytechs.jnetpcap.pro.CaptureStatistics;
import com.slytechs.jnetpcap.pro.PcapConfigurator;
import com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.descriptor.PacketDissector;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public class AbstractPacketDispatcher extends AbstractPcapDispatcher implements PacketDispatcher {

	public interface PacketDispatcherFactory<T extends PcapConfigurator<T>> {
		PacketDispatcher newInstance(
				PcapDispatcher source,
				PacketDispatcher packet,
				T context);
	}

	private final PacketDispatcher packetDispatcher;

	public AbstractPacketDispatcher(PacketDispatcher packetDispatcher, PcapDispatcher pcapDispatcher) {
		super(pcapDispatcher);

		this.packetDispatcher = Objects.requireNonNull(packetDispatcher, "packetDispatcher");
	}

	/**
	 * @param <U>
	 * @param count
	 * @param sink
	 * @param user
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketDispatcher#dispatchPacket(int,
	 *      com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket, java.lang.Object)
	 */
	@Override
	public <U> int dispatchPacket(int count, OfPacket<U> sink, U user) {
		return packetDispatcher.dispatchPacket(count, sink, user);
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketDispatcher#getDissector()
	 */
	@Override
	public PacketDissector getDissector() {
		return packetDispatcher.getDissector();
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketDispatcher#getDescriptorType()
	 */
	@Override
	public PacketDescriptorType getDescriptorType() {
		return packetDispatcher.getDescriptorType();
	}

	/**
	 * @param <U>
	 * @param count
	 * @param sink
	 * @param user
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketDispatcher#loopPacket(int,
	 *      com.slytechs.jnetpcap.pro.PcapProHandler.OfPacket, java.lang.Object)
	 */
	@Override
	public <U> int loopPacket(int count, OfPacket<U> sink, U user) {
		return packetDispatcher.loopPacket(count, sink, user);
	}

	/**
	 * @return
	 * @see com.slytechs.jnetpcap.pro.internal.PacketDispatcher#getCaptureStatistics()
	 */
	@Override
	public CaptureStatistics getCaptureStatistics() {
		return packetDispatcher.getCaptureStatistics();
	}

	@Override
	public <U> Packet processPacket(MemoryAddress pcapHdr, MemoryAddress pktData, MemorySession session) {
		return packetDispatcher.processPacket(pcapHdr, pktData, session);
	}

	@Override
	public <U> Packet processPacket(ByteBuffer buffer, MemorySegment mpacket, int caplen, int wirelen, long timestamp) {
		return packetDispatcher.processPacket(buffer, mpacket, caplen, wirelen, timestamp);
	}

	@Override
	public void onNativeCallbackException(Throwable e, int caplen, int wirelen) {
		packetDispatcher.onNativeCallbackException(e, caplen, wirelen);
	}

	@Override
	public Packet nextExPacket() throws PcapException, TimeoutException {
		return packetDispatcher.nextExPacket();
	}

	@Override
	public Packet nextPacket() throws PcapException {
		return packetDispatcher.nextPacket();
	}

}
