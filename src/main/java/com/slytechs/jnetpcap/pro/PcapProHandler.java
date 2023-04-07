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
package com.slytechs.jnetpcap.pro;

import java.lang.foreign.MemoryAddress;

import org.jnetpcap.PcapHandler;

import com.slytechs.jnet.protocol.packet.Packet;

/**
 * Marker interface for all Pcap pro packet handlers.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 *
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
		void handlePacket(U user, Packet packet);
	}

	/**
	 * Callback from a native IP fragment tracker and reassembler
	 */
	@FunctionalInterface
	public interface NativeIpfCallback {
		void handleNativeIpfCallback(
				MemoryAddress ipfDescriptor,
				MemoryAddress pktDescriptor,
				MemoryAddress pkt,
				MemoryAddress user);
	}
}