/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
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
package com.slytechs.jnet.jnetpcap.api;

import java.lang.foreign.MemorySegment;
import java.util.function.Supplier;

import com.slytechs.jnet.protocol.api.packet.Packet;
import com.slytechs.jnet.protocol.tcpip.constants.PacketDescriptorType;

/**
 * Dispatches packets to different types of packet handlers. This interface
 * provides multiple dispatch methods to support various packet handling
 * scenarios, from high-level packet objects to low-level memory access.
 * 
 * <p>
 * The dispatcher supports different types of packet handling:
 * <ul>
 * <li>Direct packet object handling</li>
 * <li>ByteBuffer-based packet handling</li>
 * <li>Byte array-based packet handling</li>
 * <li>Native memory-based packet handling</li>
 * <li>Foreign memory segment handling</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface PacketDispatcher {

	/**
	 * Processes the next available packet into a high-level packet object.
	 * 
	 * @param packet The packet object to be populated with the next packet's data
	 * @return true if a packet was successfully processed, false otherwise
	 */
	boolean nextPacket(Packet packet);

	/**
	 * Dispatches packets using ByteBuffer-based handlers.
	 * 
	 * @param <U>   The type of user data to be passed to the handler
	 * @param count The maximum number of packets to dispatch, -1 for unlimited
	 * @param cb    The callback handler that processes ByteBuffer packets
	 * @param user  User-defined data to be passed to the handler
	 * @return The number of packets actually dispatched
	 */
	<U> long dispatchBuffer(long count, PacketHandler.OfBuffer<U> cb, U user);

	/**
	 * Dispatches packets using byte array-based handlers.
	 * 
	 * @param <U>   The type of user data to be passed to the handler
	 * @param count The maximum number of packets to dispatch, -1 for unlimited
	 * @param cb    The callback handler that processes byte array packets
	 * @param user  User-defined data to be passed to the handler
	 * @return The number of packets actually dispatched
	 */
	<U> long dispatchArray(long count, PacketHandler.OfArray<U> cb, U user);

	/**
	 * Dispatches packets using native memory handlers. This method provides direct
	 * access to the native packet memory without copying.
	 * 
	 * @param count   The maximum number of packets to dispatch, -1 for unlimited
	 * @param handler The native callback handler for processing packets
	 * @param user    User data as a memory segment
	 * @return The number of packets actually dispatched
	 */
	long dispatchNative(long count, PacketHandler.OfNative handler, MemorySegment user);

	/**
	 * Dispatches packets using foreign memory segment handlers. This method
	 * provides access to packet data through memory segments.
	 * 
	 * @param <U>                  The type of user data to be passed to the handler
	 * @param count                The maximum number of packets to dispatch, -1 for
	 *                             unlimited
	 * @param memorySegmentHandler The handler for processing memory segment packets
	 * @param user                 User-defined data to be passed to the handler
	 * @return The number of packets actually dispatched
	 */
	<U> long dispatchForeign(long count, PacketHandler.OfForeign<U> memorySegmentHandler, U user);

	Packet DEFAULT_PACKET = new Packet(PacketDescriptorType.TYPE2);

	Packet getDefaultPacket();

	default <U> long dispatchPacket(PacketHandler.OfPacketConsumer cb) {
		return dispatchPacket(1, (user, packet) -> cb.accept(packet), null);
	}

	<U> long dispatchPacket(long count, PacketHandler.OfPacket<U> cb, U user);

	<U> long dispatchPacket(long count, PacketHandler.OfPacket<U> cb, U user,
			Supplier<Packet> packetFactory);

	long capturePackets(long count);
}