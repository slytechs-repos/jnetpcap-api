/*
 * Copyright 2024 Sly Technologies Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.jnet.jnetpcap;

import java.nio.ByteBuffer;
import java.util.function.Consumer;

import org.jnetpcap.PcapHandler;

import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.descriptor.IpfFragment;

/**
 * Marker interface for all Pcap pro packet handlers.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public interface NetPcapHandler extends PcapHandler {

	/**
	 * A dispatcher which dispatches high level packets with protocol header
	 * information.
	 *
	 * @param <U> the generic type
	 */
	@FunctionalInterface
	public interface OfPacket<U> extends NetPcapHandler {

		/** Empty/No-op callback handler. */
		OfPacket<?> EMPTY = (u, p) -> {};

		/**
		 * Empty/No-op callback handler.
		 *
		 * @param <U> the generic type
		 * @return the of packet
		 */
		@SuppressWarnings("unchecked")
		static <U> OfPacket<U> empty() {
			return (OfPacket<U>) EMPTY;
		}

		/**
		 * Creates a new handler that passes on new user data to the old handler. The
		 * original user data supplied is ignored.
		 *
		 * @param newUserdata the new userdata to supply
		 * @return new packet handler which overrides the original user data
		 */
		default OfPacket<U> wrapUser(U newUserdata) {
			return (u, p) -> handlePacket(newUserdata, p);
		}

		/**
		 * Wrap array.
		 *
		 * @param <U>   the generic type
		 * @param array the array
		 * @return the of packet
		 */
		static <U> OfPacket<U> wrapArray(OfPacket<U>[] array) {
			return (u, p) -> {
				for (var a : array)
					a.handlePacket(u, p);
			};
		}

		/**
		 * Handle a packet.
		 *
		 * @param user   user opaque value returned back
		 * @param packet packet data
		 */
		void handlePacket(U user, Packet packet);
	}

	/**
	 * The Interface IpfHandler.
	 */
	public interface IpfHandler {

		/**
		 * Handle ipf.
		 *
		 * @param frag      the frag
		 * @param carrier   the carrier
		 * @param ipPayload the ip payload
		 */
		void handleIpf(IpfFragment frag, ByteBuffer carrier, ByteBuffer ipPayload);
	}

	/**
	 * A dispatcher which dispatches high level packets with protocol header
	 * information.
	 */
	@FunctionalInterface
	public interface OfPacketConsumer extends NetPcapHandler, Consumer<Packet> {

		/**
		 * Accept a packet.
		 *
		 * @param packet packet data
		 */
		@Override
		void accept(Packet packet);
	}

}