package com.slytechs.jnet.jnetpcap;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.util.function.Consumer;

import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.PcapHeader;

import com.slytechs.jnet.protocol.Packet;

/**
 * A marker interface for different types of packet handlers used in packet
 * capture and processing. This interface serves as a base for specialized
 * packet handlers that can process packets in different formats (array, buffer,
 * native memory) and with different safety guarantees.
 */
public interface PacketHandler {

	/**
	 * Provides a safe packet handling mechanism using byte arrays. Each packet is
	 * received as a copy in a byte array, ensuring memory safety and allowing for
	 * packet data persistence beyond the callback scope.
	 *
	 * @param <U> The type of user-defined data to be passed through the handler
	 */
	@FunctionalInterface
	interface OfArray<U> extends PacketHandler {

		/**
		 * Handles a packet received as a byte array.
		 *
		 * @param user   User-defined data passed through the handler
		 * @param header The pcap header containing packet metadata
		 * @param packet The packet data as a byte array copy
		 */
		void handleArray(U user, PcapHeader header, byte[] packet);
	}

	/**
	 * Provides packet handling using ByteBuffers. Packets can be received either as
	 * copies or as temporal references, offering a balance between safety and
	 * performance.
	 *
	 * @param <U> The type of user-defined data to be passed through the handler
	 */
	@FunctionalInterface
	interface OfBuffer<U> extends PacketHandler {

		/**
		 * Handles a packet received as a ByteBuffer.
		 *
		 * @param user   User-defined data passed through the handler
		 * @param header The pcap header containing packet metadata
		 * @param packet The packet data as a ByteBuffer
		 */
		void handleBuffer(U user, PcapHeader header, ByteBuffer packet);
	}

	/**
	 * Provides direct access to foreign memory segments for packet handling. This
	 * is an advanced, zero-copy handler that operates directly on memory segments.
	 * The memory is only valid during the handler execution.
	 *
	 * @param <U> The type of user-defined data to be passed through the handler
	 */
	@FunctionalInterface
	interface OfForeign<U> extends PacketHandler {

		/**
		 * Handles a packet using foreign memory segments. Note: The memory segments are
		 * only valid during the execution of this method.
		 *
		 * @param user   User-defined data passed through the handler
		 * @param header The packet header as a memory segment
		 * @param packet The packet data as a memory segment
		 */
		void handleForeign(U user, MemorySegment header, MemorySegment packet);
	}

	/**
	 * Provides native callback handling for libpcap integration. This handler
	 * interfaces directly with native libpcap callbacks and automatically bridges
	 * to the handleNative method.
	 */
	@FunctionalInterface
	interface OfNative extends NativeCallback, PacketHandler {

		/**
		 * Handles packets using native memory segments. This method provides direct
		 * access to native memory without copying.
		 *
		 * @param user   User data as a memory segment
		 * @param header The packet header as a memory segment
		 * @param packet The packet data as a memory segment
		 */
		void handleNative(MemorySegment user, MemorySegment header, MemorySegment packet);

		@Override
		default void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet) {
			handleNative(user, header, packet);
		}
	}

	/**
	 * Provides high-level packet handling using the Packet object model. This
	 * handler works with parsed packet representations.
	 *
	 * @param <U> The type of user-defined data to be passed through the handler
	 */
	@FunctionalInterface
	interface OfPacket<U> extends PacketHandler {

		/**
		 * Handles a parsed packet object.
		 *
		 * @param user   User-defined data passed through the handler
		 * @param packet The parsed packet object
		 */
		void handlePacket(U user, Packet packet);
	}

	/**
	 * Provides a Java Consumer-style interface for packet handling. This handler
	 * implements the standard Java Consumer interface, allowing it to be used in
	 * streaming operations.
	 */
	interface OfPacketConsumer extends PacketHandler, Consumer<Packet> {

		/**
		 * Consumes a packet object. This method adheres to the Consumer interface
		 * contract.
		 *
		 * @param packet The packet to be consumed
		 */
		@Override
		void accept(Packet packet);
	}
}