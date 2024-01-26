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
package com.slytechs.jnet.jnetpcap.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

import org.jnetpcap.PcapException;
import org.jnetpcap.internal.PcapDispatcher;

import com.slytechs.jnet.jnetpcap.CaptureStatistics;
import com.slytechs.jnet.jnetpcap.NetPcapConfigurator;
import com.slytechs.jnet.jnetpcap.NetPcap.PcapProContext;
import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.descriptor.PacketDissector;

/**
 * The Class AbstractPacketReceiver.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public abstract class AbstractPacketReceiver
		extends AbstractPcapDispatcher
		implements PacketReceiver {

	/**
	 * A factory for creating PacketDispatcher objects.
	 *
	 * @param <T> the generic type
	 */
	public interface PacketDispatcherFactory<T extends NetPcapConfigurator<T>> {

		/**
		 * New instance.
		 *
		 * @param source  the source
		 * @param sink    the sink
		 * @param config  the config
		 * @param context the context
		 * @return the packet receiver
		 */
		PacketReceiver newInstance(
				PcapDispatcher source,
				PacketReceiver sink,
				T config,
				PcapProContext context);
	}

	/** The packet receiver. */
	private final PacketReceiver packetReceiver;

	/**
	 * Instantiates a new abstract packet receiver.
	 *
	 * @param processedPacketSink the processed packet sink
	 * @param rawPacketsource     the raw packetsource
	 */
	public AbstractPacketReceiver(PacketReceiver processedPacketSink, PcapDispatcher rawPacketsource) {
		super(rawPacketsource);

		this.packetReceiver = Objects.requireNonNull(processedPacketSink, "packetReceiver");
	}

	/**
	 * Gets the capture statistics.
	 *
	 * @return the capture statistics
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#getCaptureStatistics()
	 */
	@Override
	public CaptureStatistics getCaptureStatistics() {
		return packetReceiver.getCaptureStatistics();
	}

	/**
	 * Gets the descriptor type.
	 *
	 * @return the descriptor type
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#getDescriptorType()
	 */
	@Override
	public PacketDescriptorType getDescriptorType() {
		return packetReceiver.getDescriptorType();
	}

	/**
	 * Gets the dissector.
	 *
	 * @return the dissector
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#getDissector()
	 */
	@Override
	public PacketDissector getDissector() {
		return packetReceiver.getDissector();
	}

	/**
	 * Gets the packet with next.
	 *
	 * @return the packet with next
	 * @throws PcapException the pcap exception
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#getPacketWithNext()
	 */
	@Override
	public Packet getPacketWithNext() throws PcapException {
		return packetReceiver.getPacketWithNext();
	}

	/**
	 * Gets the packet with next extended.
	 *
	 * @return the packet with next extended
	 * @throws PcapException    the pcap exception
	 * @throws TimeoutException the timeout exception
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#getPacketWithNextExtended()
	 */
	@Override
	public Packet getPacketWithNextExtended() throws PcapException, TimeoutException {
		return packetReceiver.getPacketWithNextExtended();
	}

	/**
	 * On native callback exception.
	 *
	 * @param e       the e
	 * @param caplen  the caplen
	 * @param wirelen the wirelen
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#onNativeCallbackException(java.lang.Throwable,
	 *      int, int)
	 */
	@Override
	public void onNativeCallbackException(Throwable e, int caplen, int wirelen) {
		packetReceiver.onNativeCallbackException(e, caplen, wirelen);
	}

	/**
	 * Process packet.
	 *
	 * @param <U>       the generic type
	 * @param buffer    the buffer
	 * @param mpacket   the mpacket
	 * @param caplen    the caplen
	 * @param wirelen   the wirelen
	 * @param timestamp the timestamp
	 * @return the packet
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#processPacket(java.nio.ByteBuffer,
	 *      java.lang.foreign.MemorySegment, int, int, long)
	 */
	@Override
	public <U> Packet processPacket(ByteBuffer buffer, MemorySegment mpacket, int caplen, int wirelen, long timestamp) {
		return packetReceiver.processPacket(buffer, mpacket, caplen, wirelen, timestamp);
	}

	/**
	 * Process packet.
	 *
	 * @param <U>     the generic type
	 * @param pcapHdr the pcap hdr
	 * @param pktData the pkt data
	 * @param session the session
	 * @return the packet
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#processPacket(java.lang.foreign.MemorySegment,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.Arena)
	 */
	@Override
	public <U> Packet processPacket(MemorySegment pcapHdr, MemorySegment pktData, Arena session) {
		return packetReceiver.processPacket(pcapHdr, pktData, session);
	}

	/**
	 * Receive packet with dispatch.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#receivePacketWithDispatch(int,
	 *      com.slytechs.NetPcapHandler.pro.PcapProHandler.OfPacket, java.lang.Object)
	 */
	@Override
	public <U> int receivePacketWithDispatch(int count, OfPacket<U> sink, U user) {
		return packetReceiver.receivePacketWithDispatch(count, sink, user);
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
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#receivePacketWithDispatch(int,
	 *      com.slytechs.NetPcapHandler.pro.PcapProHandler.OfPacket, java.lang.Object,
	 *      java.util.function.Supplier)
	 */
	@Override
	public <U> int receivePacketWithDispatch(int count, OfPacket<U> sink, U user, Supplier<Packet> packetFactory) {
		return packetReceiver.receivePacketWithDispatch(count, sink, user);
	}

	/**
	 * Receive packet with loop.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 * @see com.slytechs.jnet.jnetpcap.internal.PacketReceiver#receivePacketWithLoop(int,
	 *      com.slytechs.NetPcapHandler.pro.PcapProHandler.OfPacket, java.lang.Object)
	 */
	@Override
	public <U> int receivePacketWithLoop(int count, OfPacket<U> sink, U user) {
		return packetReceiver.receivePacketWithLoop(count, sink, user);
	}

}
