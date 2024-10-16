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
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;

import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.PcapHandler.OfArray;
import org.jnetpcap.PcapHandler.OfByteBuffer;
import org.jnetpcap.PcapHeader;

import com.slytechs.jnet.jnetpcap.RawPacketPipeline.RawPacketPipe;
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
public class RawPacketPipeline
		extends AbstractPipeline<RawPacketPipe, RawPacketPipeline> {

	public static class RawProcessorContext {

		Object userData;

	}

	public interface RawPacketPipe {
		void processRawPacket(PcapHeader header, MemorySegment packet, RawProcessorContext context);
	}

	public static class RawPacketInput
			extends AbstractInput<NativeCallback, RawPacketPipe, RawPacketInput>
			implements NativeCallback {

		private RawProcessorContext context;

		/**
		 * @param headNode
		 * @param name
		 * @param inputType
		 * @param outputType
		 */
		public RawPacketInput(
				HeadNode<RawPacketPipe> headNode) {
			super(headNode, "input", PcapDataType.PCAP_NATIVE_PACKET, NetDataTypes.RAW_PACKET_PIPE);

			this.context = new RawProcessorContext();
		}

		/**
		 * @see org.jnetpcap.PcapHandler.NativeCallback#nativeCallback(java.lang.foreign.MemorySegment,
		 *      java.lang.foreign.MemorySegment, java.lang.foreign.MemorySegment)
		 */
		@Override
		public void nativeCallback(MemorySegment user, MemorySegment header, MemorySegment packet) {
			try {
				readLock.lock();

				var pcapHeader = new PcapHeader(header);

				outputData().processRawPacket(pcapHeader, packet, context);

			} finally {
				readLock.unlock();
			}
		}

	}

	public static class OfArrayOutput
			extends AbstractOutput<RawPacketPipe, PcapHandler.OfArray<?>, OfArrayOutput>
			implements RawPacketPipe {

		public OfArrayOutput(TailNode<RawPacketPipe> tailNode) {
			super(tailNode, "ofArray", NetDataTypes.RAW_PACKET_PIPE, NetDataTypes.PCAP_PACKET_OF_ARRAY);
		}

		@Override
		public void processRawPacket(PcapHeader header, MemorySegment packet, RawProcessorContext context) {
			byte[] dataArray = packet.toArray(ValueLayout.JAVA_BYTE);

			outputData().handleArray(null, header, dataArray);
		}

	}

	public static class OfBufferOutput
			extends AbstractOutput<RawPacketPipe, PcapHandler.OfByteBuffer<?>, OfBufferOutput>
			implements RawPacketPipe {

		public OfBufferOutput(TailNode<RawPacketPipe> tailNode) {
			super(tailNode, "ofBuffer", NetDataTypes.RAW_PACKET_PIPE, NetDataTypes.PCAP_PACKET_OF_BUFFER);
		}

		@Override
		public void processRawPacket(PcapHeader header, MemorySegment packet, RawProcessorContext context) {
			ByteBuffer byteBuffer = packet.asByteBuffer();

			outputData().handleByteBuffer(null, header, byteBuffer);
		}

	}

	private final EntryPoint<NativeCallback> entryPoint;
	private final EndPoint<PcapHandler.OfArray<?>> endPointOfArray;
	private final EndPoint<PcapHandler.OfByteBuffer<?>> endPointOfBuffer;

	public RawPacketPipeline(String name) {
		super(name, NetDataTypes.RAW_PACKET_PIPE);

		this.endPointOfArray = this.addOutput(RawPacketPipeline.OfArrayOutput::new)
				.createMutableEndPoint("ofArray-end")
				.empty();

		this.endPointOfBuffer = this.addOutput(RawPacketPipeline.OfBufferOutput::new)
				.createMutableEndPoint("ofBuffer-end")
				.empty();

		this.entryPoint = this.addInput(RawPacketPipeline.RawPacketInput::new)
				.createEntryPoint(name());
	}

	public EntryPoint<NativeCallback> entryPoint() {
		return entryPoint;
	}

	public EndPoint<OfArray<?>> endPointOfArray() {
		return endPointOfArray;
	}

	public EndPoint<OfByteBuffer<?>> endPointOfByteBuffer() {
		return endPointOfBuffer;
	}

}
