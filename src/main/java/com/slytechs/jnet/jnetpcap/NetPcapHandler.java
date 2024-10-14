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
package com.slytechs.jnet.jnetpcap;

import java.nio.ByteBuffer;
import java.util.function.Consumer;

import org.jnetpcap.PcapHandler;

import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.descriptor.IpfFragment;

/**
 * Marker interface for all Pcap pro packet handlers.
 * 
 * @author Mark Bednarczyk
 */
public interface NetPcapHandler extends PcapHandler {

	/**
	 * A dispatcher which dispatches high level packets with protocol header
	 * information.
	 *
	 * @param <U> the generic type
	 * @author Mark Bednarczyk
	 */
	@FunctionalInterface
	public interface OfPacket<U> extends NetPcapHandler {

		/** Empty/No-op callback handler. */
		OfPacket<?> EMPTY = (u, p) -> {};

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
		 * Handle a packet.
		 *
		 * @param user   user opaque value returned back
		 * @param packet packet data
		 */
		void handlePacket(U user, Packet packet);
	}

	/**
	 * The Interface IpfHandler.
	 *
	 * @author Mark Bednarczyk
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
	 *
	 * @author Mark Bednarczyk
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