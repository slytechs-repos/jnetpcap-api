/*
 * Copyright 2005-2025 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.sdk.jnetpcap.api;

import java.util.function.Consumer;

import com.slytechs.sdk.protocol.core.Packet;

/**
 * A marker interface for different types of packet handlers used in packet
 * capture and processing. This interface serves as a base for specialized
 * packet handlers that can process packets in different formats (array, buffer,
 * native memory) and with different safety guarantees.
 */
public interface PacketHandler {

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