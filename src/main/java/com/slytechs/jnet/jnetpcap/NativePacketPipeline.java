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

import org.jnetpcap.PcapHandler.NativeCallback;

import com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativePacketPipe;
import com.slytechs.jnet.jnetruntime.pipeline.AbstractInput;
import com.slytechs.jnet.jnetruntime.pipeline.AbstractOutput;
import com.slytechs.jnet.jnetruntime.pipeline.AbstractPipeline;
import com.slytechs.jnet.jnetruntime.pipeline.DataTransformer.InputTransformer.EntryPoint;
import com.slytechs.jnet.jnetruntime.pipeline.DataTransformer.OutputTransformer.EndPoint;
import com.slytechs.jnet.jnetruntime.pipeline.HeadNode;
import com.slytechs.jnet.jnetruntime.pipeline.TailNode;

/**
 * @author Mark Bednarczyk
 */
public class NativePacketPipeline
		extends AbstractPipeline<NativePacketPipe, NativePacketPipeline> {

	public static class NativeProcessorContext {

		MemorySegment userData;

	}

	public interface NativePacketPipe {
		void processNativePacket(MemorySegment header, MemorySegment packet, NativeProcessorContext context);
	}

	public static class PcapCallback
			extends AbstractInput<NativeCallback, NativePacketPipe, PcapCallback>
			implements NativeCallback {

		private NativeProcessorContext context;

		/**
		 * @param headNode
		 * @param name
		 * @param inputType
		 * @param outputType
		 */
		public PcapCallback(
				HeadNode<NativePacketPipe> headNode) {
			super(headNode, "input", PcapDataType.PCAP_NATIVE_PACKET, NetDataTypes.NATIVE_PACKET_PIPE);

			this.context = new NativeProcessorContext();
		}

		/**
		 * @see org.jnetpcap.PcapHandler.NativeCallback#nativeCallback(java.lang.foreign.MemorySegment,
		 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
		 */
		@Override
		public void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet) {
			context.userData = user;

			try {
				readLock.lock();
				outputData().processNativePacket(header, packet, context);

			} finally {
				readLock.unlock();
			}
		}

	}

	public static class NativeOutput
			extends AbstractOutput<NativePacketPipe, NativeCallback, NativeOutput>
			implements NativePacketPipe {

		/**
		 * @param tailNode
		 * @param name
		 * @param inputType
		 * @param outputType
		 */
		public NativeOutput(TailNode<NativePacketPipe> tailNode) {
			super(tailNode, "output", NetDataTypes.NATIVE_PACKET_PIPE, PcapDataType.PCAP_NATIVE_PACKET);
		}

		/**
		 * @see com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativePacketPipe#processNativePacket(java.lang.foreign.MemorySegment,
		 *      java.lang.foreign.MemorySegment,
		 *      com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativeProcessorContext)
		 */
		@Override
		public void processNativePacket(MemorySegment header, MemorySegment packet, NativeProcessorContext context) {
			outputData().nativeCallback(context.userData, header, packet);
		}

	}

	private EntryPoint<NativeCallback> entryPoint;
	private EndPoint<NativeCallback> endPoint;

	public NativePacketPipeline(String name) {
		super(name, NetDataTypes.NATIVE_PACKET_PIPE);

		this.endPoint = this.addOutput(NativePacketPipeline.NativeOutput::new)
				.createMutableEndPoint(name());
		this.entryPoint = this.addInput(NativePacketPipeline.PcapCallback::new)
				.createEntryPoint(name());
	}

	public NativeCallback entryPoint() {
		return entryPoint.inputData();
	}

	public void endPoint(NativeCallback out) {
		endPoint.endPointData(out);
	}
}
