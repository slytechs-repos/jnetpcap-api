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

import java.lang.foreign.MemorySegment;

import org.jnetpcap.PcapHandler.OfMemorySegment;

import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.jnetruntime.pipeline.Pipeline;

/**
 * The Class ProtocolPipeline.
 *
 * @author Mark Bednarczyk
 */
public final class ProtocolPipeline
		extends Pipeline<OfMemorySegment<?>, OfPacket<?>>
		implements OfMemorySegment<Object> {

	/** The packet dissector. */
	private final PacketProcessorGroup packetDissector;

	/**
	 * Instantiates a new protocol pipeline.
	 *
	 * @param priority the priority
	 */
	public ProtocolPipeline(int priority) {
		super(priority, new PacketProcessorGroup(0), PcapDataType.PCAP_RAW_PACKET, CoreDataType.PACKET);

		this.packetDissector = super.mainProcessor();
	}

	/**
	 * Handle segment.
	 *
	 * @param user   the user
	 * @param header the header
	 * @param Packet the packet
	 * @see org.jnetpcap.PcapHandler.OfMemorySegment#handleSegment(java.lang.Object,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public void handleSegment(Object user, MemorySegment header, MemorySegment Packet) {
		packetDissector.handleSegment(user, header, Packet);
	}

}
