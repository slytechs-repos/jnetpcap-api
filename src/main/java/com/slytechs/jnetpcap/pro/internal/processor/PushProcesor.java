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
package com.slytechs.jnetpcap.pro.internal.processor;

import java.lang.foreign.MemorySegment;

import com.slytechs.protocol.Packet;

/**
 * Base packet data chain processing interface.
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
public interface PushProcesor {

	public interface MemorySegmentProcessor extends PushProcesor {
		void processMemorySegment(MemorySegment desc, MemorySegment data);
		
		void setSink(MemorySegmentProcessor sink);
	}

	public interface PacketProcessor extends PushProcesor {
		void processPacket(Packet packet);
		
		void setSink(PacketProcessor sink);
	}
}
