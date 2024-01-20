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
public interface PcapProHandler extends PcapHandler {

	/**
	 * A dispatcher which dispatches high level packets with protocol header
	 * information.
	 *
	 * @param <U> the generic type
	 */
	@FunctionalInterface
	public interface OfPacket<U> extends PcapProHandler {
		
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
	public interface OfPacketConsumer extends PcapProHandler, Consumer<Packet> {

		/**
		 * Accept a packet.
		 *
		 * @param packet packet data
		 */
		@Override
		void accept(Packet packet);
	}

}