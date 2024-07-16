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

import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.PcapHandler.OfByteBuffer;

import com.slytechs.jnet.jnetruntime.pipeline.ProcessorGroup;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public class PcapGroup
		extends ProcessorGroup<NativeCallback, OfByteBuffer<?>>
		implements NativeCallback {

	/**
	 * @param priority
	 * @param inputType
	 * @param outputType
	 */
	PcapGroup(int priority) {
		super(priority, PcapDataType.PCAP_NATIVE, PcapDataType.PCAP_RAW);
	}

	/**
	 * @see org.jnetpcap.PcapHandler.NativeCallback#nativeCallback(java.lang.foreign.MemorySegment,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet) {
		throw new UnsupportedOperationException("not implemented yet");
	}

}
