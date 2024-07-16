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

import java.lang.foreign.MemorySegment;

import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.PcapHandler.OfByteBuffer;

import com.slytechs.jnet.jnetruntime.pipeline.Pipeline;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
public final class PcapPipeline
		extends Pipeline<NativeCallback, OfByteBuffer<?>>
		implements NativeCallback, AutoCloseable {

	private final PcapGroup mainGroup;

	PcapPipeline(int priority) {
		super(priority, new PcapGroup(0), PcapDataType.PCAP_NATIVE, PcapDataType.PCAP_RAW);

		this.mainGroup = super.mainProcessor();

		installGroup(mainGroup);
	}

	/**
	 * @see org.jnetpcap.PcapHandler.NativeCallback#nativeCallback(java.lang.foreign.MemorySegment,
	 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
	 */
	@Override
	public void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet) {
		mainGroup.nativeCallback(user, header, packet);
	}

	/**
	 * Close.
	 *
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	public void close() {
		build();
	}
}
