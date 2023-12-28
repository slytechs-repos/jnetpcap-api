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
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

import org.jnetpcap.PcapException;

import com.slytechs.jnet.jnetpcap.CaptureStatistics;
import com.slytechs.jnet.jnetpcap.PcapProHandler;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.constants.PacketDescriptorType;
import com.slytechs.jnet.protocol.descriptor.PacketDissector;

/**
 * Packet dispatcher with protocol level support.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public interface PacketReceiver extends AutoCloseable {

	/**
	 * Checks if is native packet dispatcher supported.
	 *
	 * @return true, if is native packet dispatcher supported
	 */
	static boolean isNativePacketReceiverSupported() {
		return false;
	}

	/**
	 * Java packet dispatcher.
	 *
	 * @param config the config
	 * @return the packet dispatcher
	 */
	static PacketReceiver javaPacketReceiver(
			PacketReceiverConfig config) {

		return new PacketDissectorReceiver(config);
	}

	/**
	 * Native packet dispatcher.
	 *
	 * @param config the config
	 * @return the packet dispatcher
	 */
	static PacketReceiver nativePacketReceiver(
			PacketReceiverConfig config) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Packet dispatcher.
	 *
	 * @param config the config
	 * @return the packet dispatcher
	 */
	static PacketReceiver packetReceiver(
			PacketReceiverConfig config) {

		if (isNativePacketReceiverSupported())
			return nativePacketReceiver(config);
		else
			return javaPacketReceiver(config);
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
	<U> int receivePacketWithDispatch(int count, PcapProHandler.OfPacket<U> sink, U user);

	/**
	 * Receive packet with dispatch.
	 *
	 * @param <U>           the generic type
	 * @param count         the count
	 * @param sink          the sink
	 * @param user          the user
	 * @param packetFactory the packet factory
	 * @return the int
	 */
	<U> int receivePacketWithDispatch(int count, PcapProHandler.OfPacket<U> sink, U user, Supplier<Packet> packetFactory);

	/**
	 * Gets the dissector.
	 *
	 * @return the dissector
	 */
	PacketDissector getDissector();

	/**
	 * Gets the descriptor type.
	 *
	 * @return the descriptor type
	 */
	PacketDescriptorType getDescriptorType();

	/**
	 * Loop packet.
	 *
	 * @param <U>   the generic type
	 * @param count the count
	 * @param sink  the sink
	 * @param user  the user
	 * @return the int
	 */
	<U> int receivePacketWithLoop(int count, PcapProHandler.OfPacket<U> sink, U user);

	/**
	 * Gets the capture statistics.
	 *
	 * @return the capture statistics
	 */
	CaptureStatistics getCaptureStatistics();

	/**
	 * Process packet.
	 *
	 * @param <U>     the generic type
	 * @param pcapHdr the pcap hdr
	 * @param pktData the pkt data
	 * @param session the session
	 * @return the packet
	 */
	<U> Packet processPacket(
			MemorySegment pcapHdr,
			MemorySegment pktData,
			Arena session);

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
	 */
	<U> Packet processPacket(
			ByteBuffer buffer,
			MemorySegment mpacket,
			int caplen,
			int wirelen,
			long timestamp);

	/**
	 * On native callback exception.
	 *
	 * @param e       the e
	 * @param caplen  the caplen
	 * @param wirelen the wirelen
	 */
	void onNativeCallbackException(Throwable e, int caplen, int wirelen);

	/**
	 * Next ex packet.
	 *
	 * @return the packet
	 * @throws PcapException    the pcap exception
	 * @throws TimeoutException the timeout exception
	 */
	Packet getPacketWithNextExtended() throws PcapException, TimeoutException;

	/**
	 * Next packet.
	 *
	 * @return the packet
	 * @throws PcapException the pcap exception
	 */
	Packet getPacketWithNext() throws PcapException;

	/**
	 * Close.
	 *
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	void close();

	/**
	 * Activate.
	 */
	void activate();
}
