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
import java.util.concurrent.TimeoutException;

import org.jnetpcap.PcapException;

import com.slytechs.jnetpcap.pro.CaptureStatistics;
import com.slytechs.jnetpcap.pro.PcapProHandler;
import com.slytechs.protocol.Packet;
import com.slytechs.protocol.descriptor.PacketDissector;
import com.slytechs.protocol.pack.core.constants.PacketDescriptorType;

/**
 * Packet dispatcher with protocol level support.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public interface PacketDispatcher {

	/**
	 * Checks if is native packet dispatcher supported.
	 *
	 * @return true, if is native packet dispatcher supported
	 */
	static boolean isNativePacketDispatcherSupported() {
		return false;
	}

	/**
	 * Java packet dispatcher.
	 *
	 * @param pcapHandle     the pcap handle
	 * @param breakDispatch  the break dispatch
	 * @param descriptorType the descriptor type
	 * @return the packet dispatcher
	 */
	static PacketDispatcher javaPacketDispatcher(
			PacketDispatcherConfig config) {

		return new MainPacketDispatcher(config);
	}

	/**
	 * Native packet dispatcher.
	 *
	 * @param pcapHandle     the pcap handle
	 * @param breakDispatch  the break dispatch
	 * @param descriptorType the descriptor type
	 * @return the packet dispatcher
	 */
	static PacketDispatcher nativePacketDispatcher(
			PacketDispatcherConfig config) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Packet dispatcher.
	 *
	 * @param pcapHandle     the pcap handle
	 * @param breakDispatch  the break dispatch
	 * @param descriptorType the descriptor type
	 * @return the packet dispatcher
	 */
	static PacketDispatcher packetDispatcher(
			PacketDispatcherConfig config) {

		if (isNativePacketDispatcherSupported())
			return nativePacketDispatcher(config);
		else
			return javaPacketDispatcher(config);
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
	<U> int dispatchPacket(int count, PcapProHandler.OfPacket<U> sink, U user);

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
	<U> int loopPacket(int count, PcapProHandler.OfPacket<U> sink, U user);

	CaptureStatistics getCaptureStatistics();

	<U> Packet processPacket(
			MemoryAddress pcapHdr,
			MemoryAddress pktData,
			MemorySession session);

	<U> Packet processPacket(
			ByteBuffer buffer,
			MemorySegment mpacket,
			int caplen,
			int wirelen,
			long timestamp);

	void onNativeCallbackException(Throwable e, int caplen, int wirelen);

	Packet nextExPacket() throws PcapException, TimeoutException;

	Packet nextPacket() throws PcapException;
}
