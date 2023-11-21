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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.jnetpcap.PcapHandler.NativeCallback;

import com.slytechs.jnetpcap.pro.internal.processor.PushProcesor.MemorySegmentProcessor;

/**
 * The Class NativeProcessors.
 */
public class MemorySegmentProcessors {

	private static class Empty extends MemorySegmentProcessors {

		/**
		 * @param processors
		 */
		public Empty() {
			super(Collections.emptyList());
		}

		@Override
		public NativeCallback processAndForward(NativeCallback downstreamCallback) {
			return upstreamCallback;
		}
	}

	public static MemorySegmentProcessors newInstance(List<MemorySegmentProcessor> processors) {
		if (processors.isEmpty())
			return new MemorySegmentProcessors.Empty();

		return new MemorySegmentProcessors(processors);
	}

	protected NativeCallback upstreamCallback;

	MemorySegment user;

	final MemorySegmentProcessor upstreamSinkProcessor = new MemorySegmentProcessor() {

		private MemorySegmentProcessor sink;

		@Override
		public void processMemorySegment(MemorySegment desc, MemorySegment data) {
			upstreamCallback.nativeCallback(user, desc, data);
		}

		@Override
		public void setSink(MemorySegmentProcessor sink) {
			this.sink = sink;
		}
	};

	private final MemorySegmentProcessor head;

	protected final NativeCallback processorChainCallback;

	private static MemorySegmentProcessor buildProcessorChain(List<MemorySegmentProcessor> processors) {
		assert !processors.isEmpty();
		var copy = new ArrayList<>(processors);

		MemorySegmentProcessor head = copy.remove(0), last = head;

		for (MemorySegmentProcessor p : copy)
			last.setSink(last = p);

		return last;
	}

	private MemorySegmentProcessors(List<MemorySegmentProcessor> processors) {
		assert !processors.isEmpty();
		this.head = buildProcessorChain(processors);

		this.processorChainCallback = new NativeCallback() {

			@Override
			public void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet) {
				MemorySegmentProcessors.this.user = user;

				head.processMemorySegment(header, packet);
			}
		};

	}

	public NativeCallback processAndForward(NativeCallback downstreamCallback) {
		this.upstreamCallback = downstreamCallback;

		return processorChainCallback;
	}

}