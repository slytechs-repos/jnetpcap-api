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

import java.lang.foreign.MemorySegment;

import org.jnetpcap.PcapHandler.OfMemorySegment;

import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.jnetruntime.pipeline.ProcessorGroup;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 * (p + a*(n*n)/(v*v))(V -nb) = nRT
 * T = (p + a*(n*n)/(v*v))*(V -n*b) / (n*R)
 */
public class PacketProcessorGroup
		extends ProcessorGroup<PacketProcessorGroup, OfMemorySegment<Object>, OfPacket<Object>>
		implements OfMemorySegment<Object> {

	/**
	 * @param priority
	 */
	public PacketProcessorGroup(int priority) {
		super(priority, PcapDataType.PCAP_RAW, CoreDataType.PACKET);
	}

	/**
	 * @see org.jnetpcap.PcapHandler.OfMemorySegment#handleSegment(java.lang.Object,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public void handleSegment(Object user, MemorySegment header, MemorySegment Packet) {
	}

}
